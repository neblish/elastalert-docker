import calendar
import copy
import datetime
import json
import logging
import re
import requests
import subprocess

from elasticsearch.client import Elasticsearch
from exchangelib import Credentials, Account, DELEGATE, Configuration, Mailbox, Message
from requests.exceptions import RequestException

from elastalert.alerts import Alerter, EmailAlerter, BasicMatchString, DateTimeEncoder
from elastalert.util import EAException
from elastalert.util import lookup_es_key
from elastalert.util import elastalert_logger
from elastalert.util import elasticsearch_client
from elastalert.util import ts_now, ts_to_dt
from elastalert.util import format_index


class MSendAlerter(Alerter):
    """
    ### Note: This Alerter has been deprecated in favour of the MSendServiceAlerter.

    Custom Alerter for sending events via MSEND command.
    Running this Alerter will require MSEND to be installed on the ElastAlert host.
    This Alerter has the following options available:

    Mandatory options:
    - msend_cell_name - The Cell to MSEND to (corresponds to the -n command line option)
    - msend_event_class - The event class (corresponds to the -a command line option)
    - msend_event_severity - The event severity (corresponds to the -r command line option)
    - msend_event_message - The message (corresponds to the -m command line option)

    Optionals:
    - msend_slotsetvalues - The slot set values (corresponds to the -b command line option)
      
      This can either be a string or an dictionary datatype, for example:

      msend_slotsetvalues: "key1=value1;key2=value2"

      msend_slotsetvalues:
        key1: "value1"
        key2: "value2"

      Strings can be formatted using the old-style format (%) or the new-style format (.format()). 
      When the old-style format is used, fields are accessed using %(field_name)s. 
      When the new-style format is used, fields are accessed using {match[field_name]}. 
      New-style formatting allows accessing nested fields (e.g., {match[field_1_name][field_2_name]}).
      
      In an aggregated alert, those fields will come from the first match.

    - new_style_string_format - If True, arguments are formatted using .format() rather than %. The default is False.
    """
    required_options = frozenset(['msend_cell_name','msend_event_class','msend_event_severity' ])

    known_options = [
        'msend_cell_home'
        'msend_cell_name',
        'msend_command',
        'msend_event_class',
        'msend_event_message',
        'msend_event_severity',
        'msend_slotsetvalues',
        'new_style_string_format'
    ]

    def __init__(self, rule):
        super(MSendAlerter, self).__init__(rule)
        self.cell_name = self.rule['msend_cell_name']
        self.event_class = self.rule['msend_event_class']
        self.event_severity = self.rule['msend_event_severity']

        self.cell_home = self.rule.get('msend_cell_home', '/opt/msend')
        self.msend_command = self.rule.get('msend_command', '/opt/msend/bin/msend')
        self.slotsetvalues = self.rule.get('msend_slotsetvalues')

        self.new_style_string_format = False
        if 'new_style_string_format' in self.rule and self.rule['new_style_string_format']:
            self.new_style_string_format = True

        self.last_command = []

        # Slot Set Values validation
        if (isinstance(self.slotsetvalues, basestring)):
            regex = re.compile("^\w+=[^\n;'\"]+(;(\w+=[^\n;'\"]+))*$")
            if (regex.match(self.slotsetvalues) is None):
                raise EAException('Invalid slotsetvalues format: %s' % self.slotsetvalues)


        # MSEND Command Validation
        self.shell = False
        if isinstance(self.msend_command, basestring):
            self.shell = True
            if '%' in self.msend_command:
                logging.warning('Warning! You could be vulnerable to shell injection!')

    # Alert is called
    def alert(self, matches):
        message = self.create_title(matches)
        detailed_message = self.create_alert_body(matches)

        command = [
            self.msend_command,
            '-l', self.cell_home,
            '-n', self.cell_name,
            '-a', self.event_class,
            '-r', self.event_severity,
            '-m', '\'%s\'' % message
        ]

        slotsetvalues = ''

        #
        # Transform slotsetvalues dict into a string
        if (isinstance(self.slotsetvalues, dict)):
            for k,v in self.slotsetvalues.items():
                slotsetvalues += "%s=%s;" % (k, v)
        # If slotsetvalues is a string, copy it straight across
        elif (isinstance(self.slotsetvalues, basestring)):
            slotsetvalues += self.slotsetvalues

        if slotsetvalues.endswith(';') :
            slotsetvalues = slotsetvalues[:-1] 

        try:
            if self.new_style_string_format:
                slotsetvalues = slotsetvalues.format(match=matches[0])
            else :
                slotsetvalues = slotsetvalues % matches[0]

        except KeyError as e:
            raise EAException("Error formatting command: %s" % (e))

        if (len(slotsetvalues) > 0):
            command.extend(['-b', '\'%s\'' % slotsetvalues])

        self.last_command = command
        logging.warning("MSEND Command: %s" % ' '.join(command))

        # Run command and pipe data
        try:
            subp = subprocess.Popen(' '.join(command), stdin=subprocess.PIPE, shell=self.shell)

            if self.rule.get('pipe_match_json'):
                match_json = json.dumps(matches, cls=DateTimeEncoder) + '\n'
                stdout, stderr = subp.communicate(input=match_json)
            if self.rule.get("fail_on_non_zero_exit", False) and subp.wait():
                raise EAException("Non-zero exit code while running msend command %s" % (' '.join(command)))
        except OSError as e:
            raise EAException("Error while running msend command %s: %s" % (' '.join(command), e))

    # get_info is called after an alert is sent to get data that is written back
    # to Elasticsearch in the field "alert_info"
    # It should return a dict of information relevant to what the alert does
    def get_info(self):
        return {'type': 'MSEND Alerter',
                'cell': self.rule['msend_cell_name'],
                'msend command': ' '.join(self.last_command)}



class MSendServiceAlerter(Alerter):
    """
    Custom Alerter that sends alerts to a custom MSEND Microservice
    For msend microservice please refer to neblish/msend-service docker image

    Mandatory options:
    - msend_service_url - The service endpoint for the MSend Microservice
    - msend_cell_name - The Cell to MSEND to (corresponds to the -n command line option)
    - msend_event_class - The event class (corresponds to the -a command line option)
    - msend_event_severity - The event severity (corresponds to the -r command line option)
    

    Optionals:
    - msend_event_message - The message (corresponds to the -m command line option)
    - msend_slotsetvalues - The slot set values (corresponds to the -b command line option)
      
      This can either be a string or an dictionary datatype, for example:

      msend_slotsetvalues: "key1=value1;key2=value2"

      msend_slotsetvalues:
        key1: "value1"
        key2: "value2"

      Strings can be formatted using the old-style format (%) or the new-style format (.format()). 
      When the old-style format is used, fields are accessed using %(field_name)s. 
      When the new-style format is used, fields are accessed using {match[field_name]}. 
      New-style formatting allows accessing nested fields (e.g., {match[field_1_name][field_2_name]}).
      
      For the mc_notes slot, please note that the format needs to be a "flattened" array of tuples of {hex_timestamp, user, message}, for example:
      ['0x597da640','ElasticSearch','Message #1','0x597da640','ElasticSearch','Message #2'] 

      In an aggregated alert, those fields will come from the first match.
    """
    required_options = frozenset(['msend_service_url','msend_cell_name','msend_event_class','msend_event_severity' ])

    known_options = [
        'msend_cell_name',
        'msend_event_class',
        'msend_event_message',
        'msend_event_severity',
        'msend_service_url',
        'msend_slotsetvalues',
        'new_style_string_format'
    ]
    def __init__(self, rule):
        super(MSendServiceAlerter, self).__init__(rule)
        
        self.url = self.rule['msend_service_url']
        self.cell_name = self.rule['msend_cell_name']
        self.event_class = self.rule['msend_event_class']
        self.event_severity = self.rule['msend_event_severity']

        self.event_message = self.rule.get('msend_event_message')
        self.slotsetvalues = self.rule.get('msend_slotsetvalues')

        self.new_style_string_format = False
        if 'new_style_string_format' in self.rule and self.rule['new_style_string_format']:
            self.new_style_string_format = True

        # Slot Set Values validation
        if self.slotsetvalues is not None and not isinstance(self.slotsetvalues, dict):
            raise EAException('slotsetvalues must be a dict')

    def alert(self, matches):
        message = self.create_title(matches)
        detailed_message = self.create_alert_body(matches)

        post_message = {
            'msend_cell_name': self.cell_name,
            'msend_event_class': self.event_class,
            'msend_event_severity': self.event_severity,
        }

        headers = {
            "Content-Type": "application/json",
            "Accept" : "application/json;charset=utf-8"
        }
      
        if self.event_message is not None:
            
            try:
                if self.new_style_string_format:
                    post_message['msend_event_message'] = self.event_message.format(match=matches[0])
                else:
                    post_message['msend_event_message'] = self.event_message % matches[0]
            except KeyError as e:
                raise EAException("Cannot find field in match: %s" % (e))
        else:
            post_message['msend_event_message'] = message


        if self.slotsetvalues is not None:
            slotsetvalues = {}

            for k,v in self.slotsetvalues.iteritems():
                if k == 'mc_notes':
                    continue
                try:
                    if self.new_style_string_format:
                        value = v.format(match=matches[0])
                    else :
                        value = v % matches[0]
                    slotsetvalues[k] = value

                except KeyError as e:
                    raise EAException("Cannot find key in match: %s" % (e))

            if 'mc_notes' in self.slotsetvalues:
                mc_notes = []

                for item in self.slotsetvalues['mc_notes']:
                    #elastalert_logger.info("item: %s" % item)
                    try:
                        if self.new_style_string_format:
                            itemvalue = item.format(match=matches[0])
                        else :
                            itemvalue = item % matches[0]

                    except KeyError as e:
                        raise EAException("Cannot find key in mc_notes: %s" % (e))

                    # Attempt to parse date
                    try: 
                        timestamp = ts_to_dt(itemvalue)
                        itemvalue = hex(calendar.timegm(timestamp.utctimetuple()))
                    except ValueError as e:
                        pass

                    mc_notes.append("'%s'" % itemvalue)

                slotsetvalues['mc_notes'] = '[%s]' % ','.join(mc_notes)
            post_message['msend_event_slotvalues'] = slotsetvalues

        postdata = json.dumps(post_message, cls=DateTimeEncoder)

        elastalert_logger.info('postdata: %s' % postdata)
        try:
            response = requests.post(self.url, data=postdata, headers=headers)
            response.raise_for_status()
            elastalert_logger.info(response.text)
        except RequestException as e:
            raise EAException("Error posting alert: %s" % e)
        elastalert_logger.info("HTTP POST sent")

    def get_info(self):
        return {'type': 'MSEND Service Alerter',
                'cell': self.rule['msend_cell_name']}

class ExchangeAlerter(EmailAlerter):
    """
    Custom Alerter to send alert to an Exchange server
    This alerter inherits from EmailAlerter, thus similar options are used.
    """

    required_options = frozenset(['email', 'from_addr', 'exchange_auth_file'])

    known_options = [
        'email',
        'from_addr',
        'email_add_domain',
        'email_from_field',
        'email_reply_to',
        'cc',
        'bcc',
        'exchange_host',
        'exchange_service_endpoint',
        'exchange_auth_type',
        'exchange_auth_file',
    ]

    unused_options = [
        'smtp_auth_file',
        'smtp_host',
        'smtp_port',
        'smtp_ssl'
    ]

    def __init__(self, rule):
        super(ExchangeAlerter, self).__init__(rule)

        # Mandatory fields
        if self.rule.get('exchange_auth_file'):
            self.get_account(self.rule['exchange_auth_file'])

        # Optional fields
        self.exchange_host = self.rule.get('exchange_host')
        self.exchange_service_endpoint = self.rule.get('exchange_service_endpoint')
        self.exchange_auth_type = self.rule.get('exchange_auth_type')


    def alert(self, matches):
        """
        Some of the code is a copy-and-paste from EmailAlerter.
        If anything changes in EmailAlerter ensure this method is updated accordingly.
        """
        body = self.create_alert_body(matches)

        # START copy-and-paste from EmailAlerter
        # Add JIRA ticket if it exists
        if self.pipeline is not None and 'jira_ticket' in self.pipeline:
            url = '%s/browse/%s' % (self.pipeline['jira_server'], self.pipeline['jira_ticket'])
            body += '\nJIRA ticket: %s' % (url)

        to_addr = self.rule['email']
        if 'email_from_field' in self.rule:
            recipient = lookup_es_key(matches[0], self.rule['email_from_field'])
            if isinstance(recipient, basestring):
                if '@' in recipient:
                    to_addr = [recipient]
                elif 'email_add_domain' in self.rule:
                    to_addr = [recipient + self.rule['email_add_domain']]

        # END copy-and-paste from EmailAlerter

        try:
           # setup exchangelib objects
            credentials = Credentials(username=self.user, password=self.password)

            if self.exchange_host or self.exchange_service_endpoint:
                config = Configuration(server=self.exchange_host, service_endpoint=self.exchange_service_endpoint,
                    auth_type=self.exchange_auth_type, credentials=credentials)
                account = Account(primary_smtp_address=self.from_addr, config=config, 
                    autodiscover=False, access_type=DELEGATE)
            else:
                account = Account(primary_smtp_address=self.from_addr, credentials=credentials,
                    autodiscover=True, access_type=DELEGATE)

            email_subject = self.create_title(matches)
            email_msg = body.encode('UTF-8')

            reply_to = self.rule.get('email_reply_to', self.from_addr)

            to_recipients = [ Mailbox(email_address=i) for i in to_addr ]
            cc_recipients = None
            bcc_recipients= None
            if self.rule.get('cc'):
                cc_recipients = [ Mailbox(email_address=i) for i in self.rule['cc']]

            if self.rule.get('bcc'):
                bcc_recipients = [ Mailbox(email_address=i) for i in self.rule['bcc']]

            msg = Message (
                account = account,
                folder = account.sent,
                subject = email_subject,
                body = email_msg,
                to_recipients=to_recipients,
                cc_recipients=cc_recipients,
                bcc_recipients=bcc_recipients,
            )
            
            # send the message
            msg.send_and_save()
        except Exception as e:
            raise EAException("Error connecting to Exchange host: %s" % (e))

        elastalert_logger.info("Sent email to %s" % (to_addr))       

    def get_info(self):
        return {'type': 'msexchange',
                'recipients': self.rule['email']}


class HttpPostAlerter(Alerter):
    """
    Generic Alerter to send an HTTP post to an endpoint
    """

    required_options = frozenset(['http_post_url']);

    known_options = [
        'http_post_url',
        'http_post_data',
        'http_post_data_as_json',
        'http_post_headers', # Request headers as dict
        'http_post_include_alert_subject', # Send alert subject as part of the payload
        'http_post_include_alert_body', # Send body as part of the payload
        'new_style_string_format' # Use new style string formatting 
    ]

    def __init__(self, rule):
        super(HttpPostAlerter, self).__init__(rule)
        self.url = self.rule['http_post_url']

        self.post_data = self.rule.get('http_post_data')
        self.send_as_json = self.rule.get('http_post_data_as_json', True)
        self.headers = self.rule.get('http_post_headers')
        self.include_alert_subject = self.rule.get('http_post_include_alert_subject', False)
        self.include_alert_body = self.rule.get('http_post_include_alert_body', False)
        self.new_style_string_format = self.rule.get('new_style_string_format', False)

        if self.post_data and not isinstance(self.post_data, (basestring, dict)):
            raise EAException('http_post_data must be either a string or a dict.')
        if self.headers and not isinstance(self.headers, dict):
            raise EAException('http_post_headers must be a dict.')


    def alert(self, matches):

        post_message = None
        # Default message if no data definition was defined
        if (not self.post_data):
            post_message = {
                'rule': self.rule['name'],
                'matches': matches
            }
        elif isinstance(self.post_data, basestring) and self.send_as_json:
            post_message = {'message': self.post_data}
        else: # self.post_data is of type dict
            # Apply match values to data fields (only uses matches[0])
            post_message = {}
            self.populate_match_data(self.post_data, matches[0], post_message)

        if not self.headers:
            self.headers = {}

        if self.send_as_json:
            self.headers["Content-Type"] = "application/json"
            self.headers["Accept"] = "application/json;charset=utf-8"
        else: 
            self.headers["Content-Type"] = "text/plain"
            self.headers["Accept"] = "charset=utf-8"

        # Tailor post data according to rule config
        if self.include_alert_subject:
            post_message['alert_subject'] = create_title(matches);
        if self.include_alert_body:
            post_message['alert_body'] = create_alert_body(matches);

        postdata = json.dumps(post_message, cls=DateTimeEncoder) if self.send_as_json else self.data

        elastalert_logger.info('postdata: %s' % postdata)
        try:
            response = requests.post(self.url, data=postdata, headers=self.headers)
            response.raise_for_status()
            elastalert_logger.info(response.text)
        except RequestException as e:
            raise EAException("Error posting alert: %s" % e)
        elastalert_logger.info("HTTP POST sent")

    def get_info(self):
        return {'type': 'http_post',
                'url': self.rule['http_post_url']}

    def populate_match_data(self, template, match, result):
        for key, value in template.iteritems():
            if isinstance(value, dict):
                sub_result = {}
                self.populate_match_data(value, match, sub_result)
                result[key] = sub_result
            elif self.new_style_string_format:
                result[key] = value.format(**match)
            else:
                result[key] = value % match



class ElasticSearchAlerter(Alerter):
    """
    Custom Alerter to send the alert to an ElasticSearch index.

    This alerter has the following configuration options:

    Required Attributes:
    - esalerter_index: the ElasticSearch index to send the alert to. (Required, string, no default)
    - esalerter_document_type: The target document type. (Required, String, no default)
    - esalerter_data: The document mapping itself. (Required dict, no default)

    Optional Attributes:

    The following attributes are only required if the alert is to be written to a different ElasticSearch instance to the 
    one specified in the rule:

    - esalerter_host
    - esalerter_port
    - esalerter_use_ssl
    - esalerter_username
    - esalerter_password
    - esalerter_url_prefix
    - esalerter_verify_certs

    Please refer to their "es_*" counterparts for documentation.

    - esalerter_use_strftime_index: If this is true. The alerter will format the target index using datetime.strftime.  
    - new_style_string_format: If True, arguments are formatted using .format() rather than %. The default is False.
    """
    required_options = frozenset(['esalerter_index','esalerter_document_type','esalerter_data'])

    known_options = [
        'esalerter_host',
        'esalerter_port',
        'esalerter_use_ssl',
        'esalerter_username',
        'esalerter_password',
        'esalerter_url_prefix',
        'esalerter_verify_certs',
        'esalerter_use_strftime_index', #TODO 
        'esalerter_index',
        'esalerter_document_type',
        'esalerter_data',
        'new_style_string_format'
    ]

    def __init__(self, rule):
        super(ElasticSearchAlerter, self).__init__(rule)
        self.es_index = self.rule['esalerter_index']
        self.es_doc_type = self.rule['esalerter_document_type']
        self.es_data = self.rule['esalerter_data']

        # Optional Parameter processing
        self.use_strftime_index = self.rule.get('esalerter_use_strftime_index', False)
        self.new_style_string_format = self.rule.get('new_style_string_format', False)
        
        # ElasticSearch Config processing
        temp_conf = {}
        temp_conf['es_host'] = self.rule.get('esalerter_host', self.rule['es_host'])
        temp_conf['es_port'] = self.rule.get('esalerter_port', self.rule['es_port'])

        if 'esalerter_use_ssl' in self.rule:
            temp_conf['es_use_ssl'] = self.rule.get('esalerter_use_ssl', self.rule.get('use_ssl'))
        if 'esalerter_usename' in self.rule:  
            temp_conf['es_username'] = self.rule.get('esalerter_usename', self.rule.get('es_username'))
        if 'esalerter_password' in self.rule:
            temp_conf['es_password'] = self.rule.get('esalerter_password', self.rule.get('es_password'))
        if 'esalerter_url_prefix' in self.rule:
            temp_conf['es_url_prefix'] = self.rule('esalerter_url_prefix', self.rule.get('es_url_prefix'))
        if 'esalerter_verify_certs' in self.rule:
            temp_conf['verify_certs'] = self.rule('esalerter_verify_certs', self.rule.get('verify_certs'))

        self.conf = dict((k, v) for k, v in temp_conf.iteritems() if v)
        

    # Alert is called
    def alert(self, matches):

        alert_content = {
            'alert_subject' : self.create_title(matches),
            'alert_text' : self.create_alert_body(matches)
        }
        es_document = {}
        es_all_data = dict((k,v) for k,v in matches[0].iteritems())
        es_all_data.update(alert_content)
        self.populate_match_data(self.es_data, es_all_data, es_document)



        # Init the ElasticSearchClient object
        es_client = elasticsearch_client(self.conf)

        now = ts_now()
        es_target_index = format_index(self.es_index, now, now)
        
        # Check the index exists (creates one if it does not yet exist)
        if not es_client.indices.exists(es_target_index):
            settings = {
                'index' : {
                    'number_of_shards' : 2,
                    'number_of_replicas' : 2,
                    'mapper' : {'dynamic': True }
                }
            }
            es_client.indices.create(es_target_index)
            es_client.indices.put_settings(index = es_target_index, body = settings)
            elastalert_logger.info('Index \'%s\' created' % es_target_index)

        # Write to target index
        es_client.index(
            index=es_target_index, 
            doc_type=self.es_doc_type, 
            body=es_document)
        elastalert_logger.info('Alert written into index %s' % es_target_index)


    def populate_match_data(self, template, match, result):
        for key, value in template.iteritems():
            if isinstance(value, dict):
                sub_result = {}
                self.populate_match_data(value, match, sub_result)
                result[key] = sub_result
            elif self.new_style_string_format:
                result[key] = value.format(**match)
            else:
                result[key] = value % match
    
    def get_info(self):
        return {'type': 'elasticsearch',
                'index': self.rule['esalerter_index']}
