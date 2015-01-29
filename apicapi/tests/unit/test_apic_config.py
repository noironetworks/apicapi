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
#
# @author: Ivar Lazzaro (ivar-lazzaro), Cisco Systems Inc.

import mock

from apicapi import config
from apicapi import exceptions as exc
from apicapi.tests import base
from apicapi.tests.unit.common import test_apic_common as mocked


class TestCiscoApicConfig(base.BaseTestCase, mocked.ConfigMixin):

    def setUp(self):
        super(TestCiscoApicConfig, self).setUp()
        mocked.ConfigMixin.set_up_mocks(self)
        self.apic_config._conf.register_opts(
            config.apic_opts, self.apic_config._group.name)
        self.validator = config.ConfigValidator(mock.Mock())

    def test_validate_apic_model(self):
        # Valid path
        self.validator.validate_apic_model('apicapi.db.apic_model')
        # Invalid path
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate_apic_model,
            'not.a.valid.path')

    def test_validate_mcast_ranges(self):
        # Valid range
        range = ['1.1.1.1:1.1.1.10']
        self.validator.validate_mcast_ranges(range)
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate_mcast_ranges,
            None)
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate_mcast_ranges,
            ['1.1.1.1:1.1.1.10', '1.1.2.1:1.1.2.10'])
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate_mcast_ranges,
            ['1.1.1.1:1.1.1.1000'])
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate_mcast_ranges,
            ['1.1.1.1:1.1.1.10:1.1.1.20'])
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate_mcast_ranges,
            ['1.1.1.1'])
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate_mcast_ranges,
            ['1.1.1.10:1.1.1.1'])

    def test_validate_apic_app_profile_name(self):
        valid_name = 'valid1_app2_name3_'
        self.validator.validate_apic_app_profile_name(valid_name)
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate_apic_app_profile_name,
            '$$')
        self.assertRaises(
            exc.InvalidConfig, self.validator.validate_apic_app_profile_name,
            '1$$2')

    def test_validate(self):
        self.override_config('apic_model', 'apicapi.db.apic_model',
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
