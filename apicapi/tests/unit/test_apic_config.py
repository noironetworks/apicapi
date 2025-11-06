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

import mock

from apicapi import config
from apicapi import exceptions as exc
from apicapi.tests import base
from apicapi.tests.unit.common import test_apic_common as mocked


class TestCiscoApicConfig(base.BaseTestCase, mocked.ConfigMixin):

    def setUp(self, config_group='ml2_cisco_apic'):
        self.config_group = config_group
        super(TestCiscoApicConfig, self).setUp()
        mocked.ConfigMixin.set_up_mocks(self)
        self.apic_config._conf.register_opts(
            config.apic_opts, self.apic_config._group.name)
        self.validator = config.ConfigValidator(mock.Mock())
        self.override_config('vmm_controller_host', 'somename',
                             'ml2_cisco_apic')

    def _validate(self, key, value):
        for x in self.validator.validators[key]:
            x(key, value)

    def test_validate_apic_model(self):
        # Valid path
        self._validate('apic_model', 'apicapi.tests.db.apic_model')
        # Invalid path
        self.assertRaises(
            exc.InvalidConfig, self._validate, 'apic_model',
            'not.a.valid.path')

    def test_validate_mcast_ranges(self):
        # Valid range
        range = ['1.1.1.1:1.1.1.10']
        self._validate('mcast_ranges', range)
        self.assertRaises(
            exc.InvalidConfig, self._validate, 'mcast_ranges', None)
        self.assertRaises(
            exc.InvalidConfig, self._validate, 'mcast_ranges',
            ['1.1.1.1:1.1.1.10', '1.1.2.1:1.1.2.10'])
        self.assertRaises(
            exc.InvalidConfig, self._validate, 'mcast_ranges',
            ['1.1.1.1:1.1.1.1000'])
        self.assertRaises(
            exc.InvalidConfig, self._validate, 'mcast_ranges',
            ['1.1.1.1:1.1.1.10:1.1.1.20'])
        self.assertRaises(
            exc.InvalidConfig, self._validate, 'mcast_ranges',
            ['1.1.1.1'])
        self.assertRaises(
            exc.InvalidConfig, self._validate, 'mcast_ranges',
            ['1.1.1.10:1.1.1.1'])

    def test_validate_apic_app_profile_name(self):
        valid_name = 'valid1_app2_name3_'
        self._validate('apic_app_profile_name', valid_name)
        self.assertRaises(
            exc.InvalidConfig, self._validate, 'apic_app_profile_name', '$$')
        self.assertRaises(
            exc.InvalidConfig, self._validate, 'apic_app_profile_name', '1$$2')

    def test_validate(self):
        self.override_config('apic_model', 'apicapi.tests.db.apic_model',
                             'ml2_cisco_apic')
        supported = ['apic_model', 'mcast_ranges', 'apic_app_profile_name']
        self.validator.validate(self.apic_config, *supported)
        self.validator.validate(self.apic_config, *(supported +
                                                    ['random_stuff']))
        self.validator.validate(self.apic_config)

        # Fail the validation
        self.override_config('apic_model', 'invalid-path', 'ml2_cisco_apic')
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate,
            self.apic_config, *supported)
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate,
            self.apic_config)

    def test_validate_apic_names(self):
        valid = 'valid'
        not_valid = ''
        self.override_config('apic_model', 'apicapi.tests.db.apic_model',
                             'ml2_cisco_apic')
        configurations = [
            'apic_multicast_ns_name',
            'apic_switch_pg_name',
            'openstack_user',
            'apic_domain_name',
            'apic_app_profile_name',
            'apic_vlan_ns_name',
            'apic_node_profile',
            'apic_entity_profile',
            'apic_function_profile',
            'apic_lacp_profile',
        ]
        # Validate valid
        for cfg in configurations:
            self.override_config(cfg, valid, 'ml2_cisco_apic')
        self.validator.validate(self.apic_config)

        # Raise on not valid
        for cfg in configurations:
            self.override_config(cfg, not_valid, 'ml2_cisco_apic')
            self.assertRaises(exc.InvalidConfig, self.validator.validate,
                              self.apic_config)
            # Re-set to valid value
            self.override_config(cfg, valid, 'ml2_cisco_apic')

    def test_validate_vmm_conttroller(self):
        self.override_config('apic_model', 'apicapi.tests.db.apic_model',
                             'ml2_cisco_apic')
        configuration = 'vmm_controller_host'
        # Test OK if set with Openstack vmm
        self.override_config('use_vmm', True, 'ml2_cisco_apic')
        self.override_config('apic_vmm_type', 'OpenStack', 'ml2_cisco_apic')
        self.override_config(configuration, 'some-name', 'ml2_cisco_apic')
        self.validator.validate(self.apic_config)

        # Test OK if set and no vmm
        self.override_config('use_vmm', False, 'ml2_cisco_apic')
        self.validator.validate(self.apic_config)

        # Test NOT OK if not set and VMM with different vmm_type
        self.override_config('use_vmm', True, 'ml2_cisco_apic')
        self.override_config('apic_vmm_type', 'VMWare', 'ml2_cisco_apic')
        self.override_config(configuration, None, 'ml2_cisco_apic')
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate, self.apic_config)

        # Test NOT ok if not set with vmm of Openstack type
        self.override_config('apic_vmm_type', 'OpenStack', 'ml2_cisco_apic')
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate, self.apic_config)

    def test_phy_node_segment_dict(self):
        phy_net_dict = config.create_physical_network_dict()
        self.assertEqual(2, len(phy_net_dict))
        self.assertEqual({'hosts': set(['host1', 'host2', 'host3']),
                          'segment_type': 'vlan'},
                         phy_net_dict['rack1'])
        self.assertEqual({'hosts': set(['host4', 'host5'])},
                         phy_net_dict['rack2'])

    def test_valid_encap_mode(self):
        self._validate('encap_mode', 'vlan')
        self._validate('encap_mode', 'vxlan')
        self.assertRaises(
            exc.InvalidConfig, self._validate, 'encap_mode', 'gre')


class TestCiscoApicNewConf(TestCiscoApicConfig):

    def setUp(self):
        # Switch to new-style APIC config
        super(TestCiscoApicNewConf, self).setUp(config_group='apic')


class TestConfigParse(base.BaseTestCase):

    def setUp(self):
        super(TestConfigParse, self).setUp()
        self.test_conf_files = [base.etcdir('apicapi.conf.test'),
                                base.etcdir('apicapi.conf.test.2')]
        self.mocked_get_config_files = mock.patch.object(
            config, '_get_config_files').start()
        self.mocked_get_config_files.return_value = self.test_conf_files
        self.addCleanup(self.mocked_get_config_files.stop)

    def test_parse_file(self):
        parsed = config._parse_files()
        # From file 1
        self.assertTrue('apic_physdom:phys' in parsed[0])
        # From file 2
        self.assertTrue('apic_physdom:phys3' in parsed[0])


class TestVerifySslCertificate(base.BaseTestCase, mocked.ConfigMixin):
    """Tests for verify_ssl_certificate config option supporting bool or path"""

    def setUp(self, config_group='apic'):
        self.config_group = config_group
        super(TestVerifySslCertificate, self).setUp()
        mocked.ConfigMixin.set_up_mocks(self)
        self.apic_config._conf.register_opts(
            config.apic_opts, self.apic_config._group.name)

    def test_verify_ssl_certificate_boolean_true(self):
        """Test verify_ssl_certificate accepts boolean true strings"""
        test_values = ['true', 'True', 'TRUE', 'yes', 'Yes', '1']
        for value in test_values:
            self.override_config('verify_ssl_certificate', value, 'apic')
            result = self.apic_config.verify_ssl_certificate
            self.assertEqual(value, result,
                   f"verify_ssl_certificate should store '{value}' as string")

    def test_verify_ssl_certificate_boolean_false(self):
        """Test verify_ssl_certificate accepts boolean false strings"""
        test_values = ['false', 'False', 'FALSE', 'no', 'No', '0']
        for value in test_values:
            self.override_config('verify_ssl_certificate', value, 'apic')
            result = self.apic_config.verify_ssl_certificate
            self.assertEqual(value, result,
                   f"verify_ssl_certificate should store '{value}' as string")

    def test_verify_ssl_certificate_file_path(self):
        """Test verify_ssl_certificate accepts file paths"""
        test_paths = [
            '/etc/ssl/certs/ca-certificates.crt',
            '/path/to/apic-ca-bundle.crt',
            '/usr/local/share/ca-certificates/apic.crt'
        ]
        for path in test_paths:
            self.override_config('verify_ssl_certificate', path, 'apic')
            result = self.apic_config.verify_ssl_certificate
            self.assertEqual(path, result,
               f"verify_ssl_certificate should store path '{path}' as string")

    def test_verify_ssl_certificate_default(self):
        """Test verify_ssl_certificate default value is 'false'"""
        # Don't override, should get default
        result = self.apic_config.verify_ssl_certificate
        self.assertEqual('false', result,
                   "Default verify_ssl_certificate should be 'false' string")

    def test_verify_ssl_certificate_type(self):
        """Test verify_ssl_certificate is always stored as string"""
        from oslo_config import cfg

        # Find the verify_ssl_certificate option
        opt = None
        for o in config.apic_opts:
            if o.dest == 'verify_ssl_certificate':
                opt = o
                break

        self.assertIsNotNone(opt, "verify_ssl_certificate option should exist")
        self.assertIsInstance(opt, cfg.StrOpt,
                            "verify_ssl_certificate should be StrOpt, not BoolOpt")
        self.assertEqual('false', opt.default,
                       "Default should be string 'false', not boolean False")
