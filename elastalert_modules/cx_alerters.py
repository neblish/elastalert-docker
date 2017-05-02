import json
import logging
import re
import subprocess

from elastalert.alerts import Alerter, BasicMatchString
from elastalert.util import EAException
from elastalert.util import lookup_es_key

"""
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
class MSendAlerter(Alerter):

    # By setting required_options to a set of strings
    # You can ensure that the rule config file specifies all
    # of the options. Otherwise, ElastAlert will throw an exception
    # when trying to load the rule.
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
        message = self.create_custom_title(matches)
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

"""
Custom Alerter to forward the alert to an ElasticSearch index.
"""
class ElasticSearchAlerter(Alerter):

    required_options = frozenset(['esalert_index','esalert_fieldmapping'])

    known_options = [
        'esalert_index'
        'esalert_fieldmapping',
    ]

    def __init__(self, rule):
        super(ElasticSearchAlerter, self).__init__(rule)
        self.es_index = self.rule['esalert_index']
        self.es_mapping = self.rule['esalert_mapping']

        #Future Enhancement: write to an different ES Instance

        # Alert is called
    def alert(self, matches):
        super.alert(matches) #Placeholder - need a bit more refinement
        