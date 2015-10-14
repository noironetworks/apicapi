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
import logging as log

from apicapi import apic_client


def pass_apic_client(f):
    def inner(*args, **kwargs):
        apic = apic_client.RestClient(log, "", kwargs['apic_ip'],
                                      kwargs['apic_username'],
                                      kwargs['apic_password'], kwargs['ssl'],
                                      verify=kwargs['verify'])
        return f(apic, *args, **kwargs)
    return inner


# Aggregate multiple common options into one
def neutron_options(f):
    f = click.option('--os-username', help='Openstack Username', required=True,
                     envvar='OS_USERNAME')(f)
    f = click.option('--os-password', help='Openstack Password', required=True,
                     envvar='OS_PASSWORD')(f)
    f = click.option('--os-project-id', help='Openstack Project ID',
                     required=True, envvar='OS_TENANT_NAME')(f)
    f = click.option('--os-auth-url', help='Keystone auth URL',
                     envvar='OS_AUTH_URL')(f)
    f = click.option('--os-region-name', help='Keystone region name',
                     default='RegionOne', envvar='OS_REGION_NAME')(f)
    return f


def apic_options(f):
    f = click.option('--apic-ip', help='APIC ip address', required=True)(f)
    f = click.option('--apic-username', help='APIC username', default=None)(f)
    f = click.option('--apic-password', help='APIC password', default=None)(f)
    f = click.option('--ssl/--no-ssl', default=True,
                     help='Whether to use SSL or not')(f)
    f = click.option('--secure/--no-secure', default=True,
                     help='Verify server certificate')(f)
    return f
