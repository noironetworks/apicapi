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

import click

from neutronclient.common import exceptions as exc
from neutronclient import shell

VERSION = '2.0'
NEUTRON_API_VERSION = '2.0'


class Options(object):
    os_auth_strategy = 'keystone'
    retries = 0


class ShellWrapper(shell.NeutronShell):

    def __init__(self, apiversion, **kwargs):
        self.options = Options()
        for k, v in kwargs.iteritems():
            setattr(self.options, k, v)
        self.auth_client = None
        self.api_version = apiversion


def get_neutron_client(*args, **kwargs):
    n_shell = ShellWrapper(NEUTRON_API_VERSION, **kwargs)
    n_shell.options.os_project_id = ''
    n_shell.api_version = {'network': n_shell.api_version}
    try:
        n_shell.authenticate_user()
    except exc.CommandError as e:
        raise click.BadParameter(e.message)

    return n_shell.client_manager.neutron
