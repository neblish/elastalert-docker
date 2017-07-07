import mock
import pytest
import subprocess

from elastalert.alerts import Alerter
from elastalert.alerts import BasicMatchString
from elastalert.config import load_modules
from elastalert.util import EAException
from elastalert_modules.cx_alerters import MSendAlerter, ExchangeAlerter, HttpPostAlerter, ElasticSearchAlerter
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


def test_http_post_init_validation():
    #Simple URL and map data
    rule = {
        'type': mock_rule(),
        'name': 'Test HTTP Post Rule',
        'http_post_url' : 'http://www.example.com/endpoint',
        'http_post_data' : {
            'name1':'value1'
        }
    }
    alert = HttpPostAlerter(rule)
    assert alert is not None

    #URL with String data
    alert = None
    rule = {
        'type': mock_rule(),
        'name': 'Test HTTP Post Rule',
        'http_post_url' : 'http://www.example.com/endpoint',
        'http_post_data' : 'some random string blahblah'
    }
    alert = HttpPostAlerter(rule)
    assert alert is not None

    # With list data - Exception
    alert = None
    rule = {
        'type': mock_rule(),
        'name': 'Test HTTP Post Rule',
        'http_post_url' : 'http://www.example.com/endpoint',
        'http_post_data' : ['value1', 'value2', 'value3']
    }

    with pytest.raises(EAException):
        alert = HttpPostAlerter(rule)

    # Valid Header Data
    alert = None
    rule = {
        'type': mock_rule(),
        'name': 'Test HTTP Post Rule',
        'http_post_url' : 'http://www.example.com/endpoint',
        'http_post_headers' : {
            'name1':'value1'
        }
    }
    alert = HttpPostAlerter(rule)
    assert alert is not None

    # Invalid headers
    alert = None
    rule = {
        'type': mock_rule(),
        'name': 'Test HTTP Post Rule',
        'http_post_url' : 'http://www.example.com/endpoint',
        'http_post_headers' : ['blahblah']
    }
    with pytest.raises(EAException):
        alert = HttpPostAlerter(rule)

def test_http_post_mandatory_params():
    # Posting - only mandatory parameters
    alert = None
    rule = {
        'type': mock_rule(),
        'name': 'Test HTTP Post Rule',
        'http_post_url' : 'http://www.example.com/endpoint',
    }
    match = {'@timestamp': '2014-01-01T00:00:00',
         'somefield': 'foobarbaz',
         'nested': {'field': 1}}
    alert = HttpPostAlerter(rule)

    expected_data = '{"matches": [{"@timestamp": "2014-01-01T00:00:00", "somefield": "foobarbaz", "nested": {"field": 1}}], "rule": "Test HTTP Post Rule"}'
    expected_headers = {'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8'}
    with mock.patch("elastalert_modules.cx_alerters.requests.post") as mock_request:
        alert.alert([match])
    mock_request.assert_called_with('http://www.example.com/endpoint', data=expected_data, headers=expected_headers)

def test_http_post_additional_headers():
    # Posting - Additional Headers
    alert = None
    rule = {
        'type': mock_rule(),
        'name': 'Test HTTP Post Rule',
        'http_post_url' : 'http://www.example.com/endpoint',
        'http_post_headers' : {
            'name1':'value1'
        }
    }
    match = {'@timestamp': '2014-01-01T00:00:00',
         'somefield': 'foobarbaz',
         'nested': {'field': 1}}
    alert = HttpPostAlerter(rule)

    expected_data = '{"matches": [{"@timestamp": "2014-01-01T00:00:00", "somefield": "foobarbaz", "nested": {"field": 1}}], "rule": "Test HTTP Post Rule"}'
    expected_headers = {'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8', 'name1': 'value1'}
    with mock.patch("elastalert_modules.cx_alerters.requests.post") as mock_request:
        alert.alert([match])
    mock_request.assert_called_with('http://www.example.com/endpoint', data=expected_data, headers=expected_headers)

def test_http_post_old_style_post_data():
    # Posting - Data formatting (old style)
    alert = None
    rule = {
        'type': mock_rule(),
        'name': 'Test HTTP Post Rule',
        'http_post_url' : 'http://www.example.com/endpoint',
        'http_post_headers' : {
            'name1':'value1'
        },
        'http_post_data' : {
            '@timestamp' : '%(@timestamp)s',
            'somefield1' : '%(somefield)s'
        },
        'new_style_string_format': False
    }
    match = {'@timestamp': '2014-01-01T00:00:00',
         'somefield': 'foobarbaz',
         'nested': {'field': 1}}
    alert = HttpPostAlerter(rule)

    expected_data = '{"@timestamp": "2014-01-01T00:00:00", "somefield1": "foobarbaz"}'
    expected_headers = {'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8', 'name1': 'value1'}
    with mock.patch("elastalert_modules.cx_alerters.requests.post") as mock_request:
        alert.alert([match])
    mock_request.assert_called_with('http://www.example.com/endpoint', data=expected_data, headers=expected_headers)

def test_http_post_new_style_post_data():
    # Posting - Data formatting (new style)
    alert = None
    rule = {
        'type': mock_rule(),
        'name': 'Test HTTP Post Rule',
        'http_post_url' : 'http://www.example.com/endpoint',
        'http_post_headers' : {
            'name1':'value1'
        },
        'http_post_data' : {
            '@timestamp' : '{@timestamp}',
            'somefield1' : '{somefield}'
        },
        'new_style_string_format': True
    }
    match = {'@timestamp': '2014-01-01T00:00:00',
         'somefield': 'foobarbaz',
         'nested': {'field': 1}}
    alert = HttpPostAlerter(rule)

    expected_data = '{"@timestamp": "2014-01-01T00:00:00", "somefield1": "foobarbaz"}'
    expected_headers = {'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8', 'name1': 'value1'}
    with mock.patch("elastalert_modules.cx_alerters.requests.post") as mock_request:
        alert.alert([match])
    mock_request.assert_called_with('http://www.example.com/endpoint', data=expected_data, headers=expected_headers)

def test_http_post_post_data_nested_dict():
    # Posting - nested post data structures (new style)
    alert = None
    rule = {
        'type': mock_rule(),
        'name': 'Test HTTP Post Rule',
        'http_post_url' : 'http://www.example.com/endpoint',
        'http_post_headers' : {
            'name1':'value1'
        },
        'http_post_data' : {
            '@timestamp' : '{@timestamp}',
            'data': {
                'somefield1' : '{somefield}',
                'nestedfield' : '{nested[field]}'
            }
        },
        'new_style_string_format': True
    }
    match = {'@timestamp': '2014-01-01T00:00:00',
         'somefield': 'foobarbaz',
         'nested': {'field': 1}}
    alert = HttpPostAlerter(rule)

    expected_data = '{"@timestamp": "2014-01-01T00:00:00", "data": {"nestedfield": "1", "somefield1": "foobarbaz"}}'
    expected_headers = {'Content-Type': 'application/json', 'Accept': 'application/json;charset=utf-8', 'name1': 'value1'}
    with mock.patch("elastalert_modules.cx_alerters.requests.post") as mock_request:
        alert.alert([match])
    mock_request.assert_called_with('http://www.example.com/endpoint', data=expected_data, headers=expected_headers)

def test_esalerter_init_validation():
    # All mandatory fields present 
    rule = {
        'type': mock_rule(),
        'name': 'Test ElastSearchAlerter Rule',
        'es_host': '127.0.0.1',
        'es_port': '9200',
        'esalerter_index' : 'logstash-example',
        'esalerter_document_type': 'example',
        'esalerter_data' : {
            'field1' : '{field1}',
            'field2' : '{field2}'
        }

    }
    alert = ElasticSearchAlerter(rule)
    assert alert is not None

    