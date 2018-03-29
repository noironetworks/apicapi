# Copyright (c) 2014 Cisco Systems
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import contextlib
import mock
from OpenSSL import crypto
import requests
import tempfile

try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg

from apicapi import apic_client as apic
from apicapi import apic_mapper as apic_mapper
from apicapi import config as apic_cfg
from apicapi.tests.unit.common import config  # noqa


OK = requests.codes.ok

APIC_HOSTS = ['fake.controller.local']
APIC_PORT = 7580
APIC_USR = 'notadmin'
APIC_PWD = 'topsecret'
APIC_USR_CERT_NAME = 'notadmin-cert'

APIC_TENANT = 'citizen14'
APIC_NETWORK = 'network99'
APIC_L3CTX = 'layer3context'
APIC_AP = 'appProfile001'
APIC_EPG = 'endPointGroup001'

APIC_CONTRACT = 'signedContract'

APIC_SYSTEM_ID = 'sysid'
APIC_DOMAIN = 'cumuloNimbus'
APIC_L3EXT_DOMAIN = '%s_l3ext' % APIC_SYSTEM_ID
APIC_SW_PG_NAME = 'switch_pg'

APIC_NODE_PROF = 'red'
APIC_FUNC_PROF = 'beta'
APIC_ATT_ENT_PROF = 'delta'
APIC_L3EXT_FUNC_PROF = '%s_l3ext_function_profile' % APIC_SYSTEM_ID
APIC_L3EXT_ATT_ENT_PROF = '%s_l3ext_entity_profile' % APIC_SYSTEM_ID
APIC_VLAN_NAME = 'gamma'
APIC_VLANID_FROM = 2900
APIC_VLANID_TO = 2999
APIC_VLAN_FROM = 'vlan-%d' % APIC_VLANID_FROM
APIC_VLAN_TO = 'vlan-%d' % APIC_VLANID_TO

APIC_ROUTER = apic_mapper.ApicName('router', 'router_id')

APIC_EXT_SWITCH = '203'
APIC_EXT_MODULE = '1'
APIC_EXT_PORT = '34'
APIC_EXT_ENCAP = 'vlan-100'
APIC_EXT_CIDR_EXPOSED = '10.10.40.2/16'
APIC_EXT_GATEWAY_IP = '10.10.40.1'


class ControllerMixin(object):

    """Mock the controller for APIC driver and service unit tests."""

    def __init__(self):
        self.response = None

    def set_up_mocks(self):
        # The mocked responses from the server are lists used by
        # mock.side_effect, which means each call to post or get will
        # return the next item in the list. This allows the test cases
        # to stage a sequence of responses to method(s) under test.
        self.response = {'post': [], 'get': []}
        self.reset_reponses()
        self.log = mock.Mock()

    def create_pvt_key_file(self):
        self.clean_up_pvt_key_file()
        self.pvt_key_file = tempfile.NamedTemporaryFile()
        pk = crypto.PKey()
        pk.generate_key(crypto.TYPE_RSA, 1024)
        self.pvt_key_file.write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, pk))
        self.pvt_key_file.flush()
        self.certificate = crypto.X509()
        self.certificate.set_pubkey(pk)
        self.certificate.sign(pk, 'sha256')
        return self.pvt_key_file.name

    def clean_up_pvt_key_file(self):
        try:
            self.pvt_key_file.close()
        except AttributeError:
            pass

    def reset_reponses(self, req=None):
        # Clear all staged responses.
        reqs = req and [req] or ['post', 'get']  # Both if none specified.
        for req in reqs:
            del self.response[req][:]
            self.restart_responses(req)

    def restart_responses(self, req):
        responses = mock.MagicMock(side_effect=self.response[req])
        if req == 'post':
            requests.Session.post = responses
        elif req == 'get':
            requests.Session.get = responses

    def enable_signature_check(self):
        self.saved_get_responder = requests.Session.get
        self.saved_post_responder = requests.Session.post
        requests.Session.get = (
            mock.MagicMock(side_effect=self._verify_and_respond_for_get))
        requests.Session.post = (
            mock.MagicMock(side_effect=self._verify_and_respond_for_post))

    def _verify_and_respond_for_get(self, *args, **kwargs):
        self._verify_signature('GET', *args, **kwargs)
        return self.saved_get_responder(*args, **kwargs)

    def _verify_and_respond_for_post(self, *args, **kwargs):
        self._verify_signature('POST', *args, **kwargs)
        return self.saved_post_responder(*args, **kwargs)

    def _verify_signature(self, req, *args, **kwargs):
        """ Throws exception if verification fails """
        cookies = kwargs.get('cookies', {})
        if 'APIC-Request-Signature' not in cookies:
            return
        url = args[0]
        payload = req + url[url.find('/api'):] + kwargs.get('data', '')
        cert_dn = ('uni/userext/user-%s/usercert-%s' %
            (APIC_USR, APIC_USR_CERT_NAME))
        if cookies.get('APIC-Certificate-DN') != cert_dn:
            raise Exception("Certificate DN mismatch")
        if (cookies.get('APIC-Certificate-Algorithm') != 'v1.0' or
            cookies.get('APIC-Certificate-Fingerprint') != 'fingerprint'):
            raise Exception("Signature verification algorithm mismatch")
        crypto.verify(self.certificate,
                      base64.b64decode(cookies.get('APIC-Request-Signature')),
                      payload, 'sha256')

    def mock_response_for_post(self, mo, **attrs):
        attrs['debug_mo'] = mo  # useful for debugging
        self._stage_mocked_response('post', OK, mo, **attrs)

    def mock_response_for_get(self, mo, **attrs):
        self._stage_mocked_response('get', OK, mo, **attrs)

    def mock_append_to_response(self, mo, **attrs):
        # Append a MO to the last get response.
        mo_attrs = attrs and {mo: {'attributes': attrs}} or {}
        self.response['get'][-1].json.return_value['imdata'].append(mo_attrs)

    def mock_error_post_response(self, status, **attrs):
        self._stage_mocked_response('post', status, 'error', **attrs)

    def mock_error_get_response(self, status, **attrs):
        self._stage_mocked_response('get', status, 'error', **attrs)

    def _stage_mocked_response(self, req, mock_status, mo, **attrs):
        response = mock.MagicMock()
        response.status_code = mock_status
        mo_attrs = attrs and [{mo: {'attributes': attrs}}] or []
        response.json.return_value = {'imdata': mo_attrs}
        self.response[req].append(response)

    def mock_responses_for_create(self, obj):
        self._mock_container_responses_for_create(
            apic.ManagedObjectClass(obj).container)
        name = '-'.join([obj, 'name'])  # useful for debugging
        self._stage_mocked_response('post', OK, obj, name=name)

    def mock_responses_for_create_if_not_exists(self, obj):
        self.mock_response_for_get(obj)
        self.mock_responses_for_create(obj)

    def _mock_container_responses_for_create(self, obj):
        # Recursively generate responses for creating obj's containers.
        if obj:
            mo = apic.ManagedObjectClass(obj)
            if mo.can_create:
                if mo.container:
                    self._mock_container_responses_for_create(mo.container)
                name = '-'.join([obj, 'name'])  # useful for debugging
                self._stage_mocked_response('post', OK, obj, debug_name=name)

    def mock_apic_manager_login_responses(self, timeout=300):
        # APIC Manager tests are based on authenticated session
        self.mock_response_for_post('aaaLogin', userName=APIC_USR,
                                    token='ok', refreshTimeoutSeconds=timeout)

    def mock_response_for_certificate_fetch(self, cert_name):
        self.mock_response_for_get('aaaUserCert', name=cert_name)

    def assert_responses_drained(self, req=None):
        """Fail if all the expected responses have not been consumed."""
        request = {'post': self.session.post, 'get': self.session.get}
        reqs = req and [req] or ['post', 'get']  # Both if none specified.
        for req in reqs:
            try:
                request[req]('some url')
            except StopIteration:
                pass
            else:
                # User-friendly error message
                msg = req + ' response queue not drained'
                self.fail(msg=msg)

    def get_top_container(self, mo):
        while mo.container:
            mo = apic.ManagedObjectClass(mo.container)
        return mo

    @contextlib.contextmanager
    def fake_transaction(self, *args, **kwargs):
        yield 'transaction'


class ConfigMixin(object):

    """Mock the config for APIC driver and service unit tests."""

    def __init__(self):
        self.mocked_parser = None

    def set_up_mocks(self):

        # Configure global option apic_system_id
        cfg.CONF.set_override('apic_system_id', APIC_SYSTEM_ID)
        cfg.CONF.set_override('config_file', 'etc/conf_sample.ini')

        # Configure the Cisco APIC mechanism driver
        apic_test_config = {
            'apic_hosts': APIC_HOSTS,
            'apic_username': APIC_USR,
            'apic_password': APIC_PWD,
            'apic_domain_name': APIC_DOMAIN,
            'apic_vlan_ns_name': APIC_VLAN_NAME,
            'apic_vlan_range': '%d:%d' % (APIC_VLANID_FROM, APIC_VLANID_TO),
            'apic_node_profile': APIC_NODE_PROF,
            'apic_entity_profile': APIC_ATT_ENT_PROF,
            'apic_function_profile': APIC_FUNC_PROF,
        }
        for opt, val in apic_test_config.items():
            self.override_config(opt, val, self.config_group)
        self.apic_config = cfg.CONF.ml2_cisco_apic

        # Configure switch topology
        apic_mock_cfg = {
            'apic_switch:101': {'ubuntu1,ubuntu2': ['3/11']},
            'apic_switch:102': {'rhel01|eth1,rhel02|eth2': ['4/21'],
                                'rhel03|eth3': ['1/4/22'],
                                'pod_id': '2'},
            'apic_physical_network:rack1': {
                'hosts': ['host1, host2, host3 '],
                'segment_type': ['vlan'],
            },
            'apic_physical_network:rack2': {
                'hosts': [' host4, , host5'],
            },
        }
        self.switch_dict = {
            '101': {
                '3/11': ['ubuntu1', 'ubuntu2'],
            },
            '102': {
                '4/21': ['rhel01|eth1', 'rhel02|eth2'],
                '1/4/22': ['rhel03|eth3'],
                'pod_id': '2'
            },
        }
        self.vpc_dict = {
            '201': '202',
            '202': '201',
        }
        self.external_network_dict = {
            APIC_NETWORK + '-name': {
                'switch': APIC_EXT_SWITCH,
                'port': APIC_EXT_MODULE + '/' + APIC_EXT_PORT,
                'encap': APIC_EXT_ENCAP,
                'cidr_exposed': APIC_EXT_CIDR_EXPOSED,
                'gateway_ip': APIC_EXT_GATEWAY_IP,
            },
            APIC_NETWORK + '-1-name': {
                'switch': APIC_EXT_SWITCH,
                'port': APIC_EXT_MODULE + '/' + APIC_EXT_PORT,
                'encap': APIC_EXT_ENCAP,
                'cidr_exposed': APIC_EXT_CIDR_EXPOSED,
                'gateway_ip': APIC_EXT_GATEWAY_IP,
            },
            APIC_NETWORK + '-pre-name': {
                'preexisting': 'true',
            },
        }
        self.vlan_ranges = ['physnet0', 'physnet1:100:199']
        self.old_parser = apic_cfg._parse_files
        self.mocked_parser = mock.patch.object(
            apic_cfg, '_parse_files').start()
        self.mocked_parser.return_value = [apic_mock_cfg]
        self.addCleanup(self.restore_parser)

    def restore_parser(self):
        apic_cfg._parse_files = self.old_parser

    def override_config(self, opt, val, group=None):
        cfg.CONF.set_override(opt, val, group)

    def clear_config(self, opt, group=None):
        cfg.CONF.clear_override(opt, group)


class DbModelMixin(object):

    """Mock the DB models for the APIC driver and service unit tests."""

    def __init__(self):
        self.mocked_session = None

    def set_up_mocks(self):
        self.mocked_session = mock.Mock()
        get_session = mock.patch('apicapi.tests.db.api.get_session').start()
        get_session.return_value = self.mocked_session

    def mock_db_query_all_return(self, value):
        """Mock db.session.query().all() to return value."""
        query = self.mocked_session.query.return_value
        query.all.return_value = value

    def mock_db_query_filterby_first_return(self, value):
        """Mock db.session.query().filterby().first() to return value."""
        query = self.mocked_session.query.return_value
        query.filter_by.return_value.first.return_value = value

    def mock_db_query_filterby_distinct_return(self, value):
        """Mock db.session.query().filterby().distinct() to return value."""
        query = self.mocked_session.query.return_value
        query.filter_by.return_value.distinct.return_value = value

    def mock_db_query_filterby_all_return(self, value):
        """Mock db.session.query().filterby().all() to return value."""
        query = self.mocked_session.query.return_value
        query.filter_by.return_value.all.return_value = value

    def mock_db_query_filter3_distinct_return(self, value):
        """Mock to return value.
        db.session.query().filter().filter().filter().distinct()
        """
        query = self.mocked_session.query.return_value
        query_filter3 = \
            query.filter.return_value.filter.return_value.filter.return_value
        query_filter3.distinct.return_value = value

    def mock_db_query_distinct_return(self, value):
        """Mock db.session.query().distinct() to return value."""
        query = self.mocked_session.query.return_value
        query.distinct.return_value = value


class FakeQuery(list):

    def __init__(self, *args):
        self.extend(args)

    def count(self):
        return len(self)
