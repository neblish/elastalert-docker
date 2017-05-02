import mock
import pytest
import subprocess

from elastalert.alerts import Alerter
from elastalert.alerts import BasicMatchString
from elastalert_modules.cx_alerters import MSendAlerter
from tests.alerts_test import mock_rule

# Test with just the mandatory parameters
def test_msend_mandatory_params():
    rule = {
        'type': mock_rule(),
        'alert_subject': 'Alert Subject',
        'alert_text': 'Alert Text',
        'msend_cell_name': 'somecellname',
        'msend_event_class': 'EVENT',
        'msend_event_severity': 'WARNING',
    }
    alert = MSendAlerter(rule)
    match = {'@timestamp': '2014-01-01T00:00:00',
             'somefield': 'foobarbaz',
             'nested': {'field': 1}}
    with mock.patch("elastalert_modules.cx_alerters.subprocess.Popen") as mock_popen:
        alert.alert([match])
    mock_popen.assert_called_with("/opt/msend/bin/msend -l /opt/msend -n somecellname -a EVENT -r WARNING -m 'Alert Subject'", stdin=subprocess.PIPE, shell=True)

# Test for alert_subject_args
def test_msend_alert_subject_args():
    rule = {
        'type': mock_rule(),
        'alert_subject': 'Alert Subject: {0} - {1}',
        'alert_subject_args': ['@timestamp', 'somefield'],
        'alert_text': 'Alert Text',
        'msend_cell_name': 'somecellname',
        'msend_event_class': 'EVENT',
        'msend_event_severity': 'WARNING',
    }
    match = {'@timestamp': '2014-01-01T00:00:00',
         'somefield': 'foobarbaz',
         'nested': {'field': 1}}
    alert = MSendAlerter(rule)
    with mock.patch("elastalert_modules.cx_alerters.subprocess.Popen") as mock_popen:
        alert.alert([match])
    mock_popen.assert_called_with("/opt/msend/bin/msend -l /opt/msend -n somecellname -a EVENT -r WARNING -m 'Alert Subject: 2014-01-01T00:00:00 - foobarbaz'", stdin=subprocess.PIPE, shell=True)

# Test for slotsetvalues (string: correct format)
def test_msend_slotsetvalues_string_type():
    rule = {
        'type': mock_rule(),
        'alert_subject': 'Alert Subject',
        'alert_text': 'Alert Text',
        'msend_cell_name': 'somecellname',
        'msend_event_class': 'EVENT',
        'msend_event_severity': 'WARNING',
        'msend_slotsetvalues' : 'mc_host=testhost;mc_tool=Elasticsearch;mc_object=test object;mc_object_class=test object class;mc_parameter=test parameter;mc_parameter_value=test parameter value',
    }
    match = {'@timestamp': '2014-01-01T00:00:00',
         'somefield': 'foobarbaz',
         'nested': {'field': 1}}
    alert = MSendAlerter(rule)
    with mock.patch("elastalert_modules.cx_alerters.subprocess.Popen") as mock_popen:
        alert.alert([match])
    mock_popen.assert_called_with("/opt/msend/bin/msend -l /opt/msend -n somecellname -a EVENT -r WARNING -m 'Alert Subject' -b 'mc_host=testhost;mc_tool=Elasticsearch;mc_object=test object;mc_object_class=test object class;mc_parameter=test parameter;mc_parameter_value=test parameter value'", stdin=subprocess.PIPE, shell=True)

    #TODO: Write test case for incorrect slotsetvalue string format

# Test for slotsetvalues (dictionary format) - plain text values
def test_msend_slotsetvalues_dict_plaintext():
    rule = {
        'type': mock_rule(),
        'alert_subject': 'Alert Subject',
        'alert_text': 'Alert Text',
        'msend_cell_name': 'somecellname',
        'msend_event_class': 'EVENT',
        'msend_event_severity': 'WARNING',
        'msend_slotsetvalues' : {
            'mc_host': 'testhost',
            'mc_tool': 'Elasticsearch'
       	}
    }
    match = {'@timestamp': '2014-01-01T00:00:00',
         'somefield': 'foobarbaz',
         'nested': {'field': 1}}
    alert = MSendAlerter(rule)
    with mock.patch("elastalert_modules.cx_alerters.subprocess.Popen") as mock_popen:
        alert.alert([match])
    mock_popen.assert_called_with("/opt/msend/bin/msend -l /opt/msend -n somecellname -a EVENT -r WARNING -m 'Alert Subject' -b 'mc_tool=Elasticsearch;mc_host=testhost'", stdin=subprocess.PIPE, shell=True)

# Test for slotsetvalues (dictionary format) - variable substitution with old string format
def test_msend_slotsetvalues_dict_variable_subst_oldstrformat():
    rule = {
        'type': mock_rule(),
        'alert_subject': 'Alert Subject',
        'alert_text': 'Alert Text',
        'msend_cell_name': 'somecellname',
        'msend_event_class': 'EVENT',
        'msend_event_severity': 'WARNING',
        'msend_slotsetvalues' : {
            'mc_host': 'testhost',
            'mc_tool': 'Elasticsearch',
            'mc_long_msg': '%(somefield)s',
       	}
    }
    match = {'@timestamp': '2014-01-01T00:00:00',
         'somefield': 'foobarbaz',
         'nested': {'field': 1}}
    alert = MSendAlerter(rule)
    with mock.patch("elastalert_modules.cx_alerters.subprocess.Popen") as mock_popen:
        alert.alert([match])
    mock_popen.assert_called_with("/opt/msend/bin/msend -l /opt/msend -n somecellname -a EVENT -r WARNING -m 'Alert Subject' -b 'mc_long_msg=foobarbaz;mc_tool=Elasticsearch;mc_host=testhost'", stdin=subprocess.PIPE, shell=True)

# Test for slotsetvalues (dictionary format) - variable substitution with new string format
def test_msend_slotsetvalues_dict_variable_subst_newstrformat():
    rule = {
        'type': mock_rule(),
        'new_style_string_format': True,
        'alert_subject': 'Alert Subject',
        'alert_text': 'Alert Text',
        'msend_cell_name': 'somecellname',
        'msend_event_class': 'EVENT',
        'msend_event_severity': 'WARNING',
        'msend_slotsetvalues' : {
            'mc_host': 'testhost',
            'mc_tool': 'Elasticsearch',
            'mc_long_msg': '{match[somefield]}',
            'mc_more_msg': '{match[nested][field]}'
       	}
    }
    match = {'@timestamp': '2014-01-01T00:00:00',
         'somefield': 'foobarbaz',
         'nested': {'field': 1}}
    alert = MSendAlerter(rule)
    with mock.patch("elastalert_modules.cx_alerters.subprocess.Popen") as mock_popen:
        alert.alert([match])
    mock_popen.assert_called_with("/opt/msend/bin/msend -l /opt/msend -n somecellname -a EVENT -r WARNING -m 'Alert Subject' -b 'mc_long_msg=foobarbaz;mc_more_msg=1;mc_tool=Elasticsearch;mc_host=testhost'", stdin=subprocess.PIPE, shell=True)

