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
import mock
import requests.exceptions as r_exc

from apicapi import apic_client
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
            '--os-auth-url', 'http://127.0.0.1/v2',
            '--os-username', 'user']
        self.apic_command_options = [
            '--apic-ip', '127.0.0.1',
            '--apic-username', 'admin',
            '--apic-password', 'mydirtylittlesecret',
        ]
        self.neutron = mock.patch(
            'neutronclient.common.clientmanager.ClientManager.neutron').start()

    def test_neutron_sync(self):
        result = self.invoke(shell.apicapi, [
            'neutron-sync'] + self.neutron_command_options)
        self.assertFalse(result.exception)
        self.neutron.create_network.assert_called_once_with(
            {'network': {'name': 'apic-sync-network'}})

    def test_neutron_require_token(self):
        result = self.invoke(shell.apicapi, [
            'neutron-sync'] + self.neutron_command_options +
            ['--os-url', 'someurl'])
        self.assertIsNotNone(result.exception)
        self.assertTrue(
            'Error: Invalid value: You must provide a token via either '
            '--os-token or env[OS_TOKEN]' in result.output)

    def test_apic_client_ssl_error(self):
        apic_client.RestClient = mock.Mock(side_effect=r_exc.SSLError)
        result = self.invoke(shell.apicapi, [
            'route-reflector-create'] + self.apic_command_options)
        self.assertIsNotNone(result.exception)
        self.assertTrue("'--no-secure' to skip certificate validation" in
                        result.output)
