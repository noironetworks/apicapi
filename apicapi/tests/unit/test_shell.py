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

from click import testing

from apicapi.tests import base
from apicapi.tools.cli import shell


class TestShell(base.BaseTestCase):

    def setUp(self):
        super(TestShell, self).setUp()
        self.runner = testing.CliRunner()
        self.invoke = self.runner.invoke
        self.neutron_command_options = [
            '--os-project-id', 'id',
            '--os-password', 'pwd',
            '--os-auth-url', 'url',
            '--os-username', 'user']

    def test_neutron_sync(self):
        result = self.invoke(shell.apicapi, [
            'neutron-sync'] + self.neutron_command_options)
        self.assertFalse(result.exception)
        self.assertEqual(result.output, 'user\n')
