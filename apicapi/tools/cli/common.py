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
from apicapi.tools.cli.neutron import client as n_client


def pass_neutron_client(f):
    """Utility decorator for Neutron client.

    Provided that the options defined in @os_options are present, this
    decorator can use them to create the neutron client and pass it down to the
    command. This decorator is typically user -after- @os_options for Neutron
    commands.
    """
    def inner(*args, **kwargs):
        neutron = n_client.get_neutron_client(*args, **kwargs)
        return f(neutron, *args, **kwargs)
    return inner


def pass_apic_client(f):
    """Utility decorator for APIC client.

    Provided that the options defined in @apic_options are present, this
    decorator can use them to create the APIC client and pass it down to the
    command. This decorator is typically user -after- @apic_options for APIC
    commands.
    """
    def inner(*args, **kwargs):
        try:
            apic = apic_client.RestClient(log, "", [kwargs['apic_ip']],
                                          kwargs['apic_username'],
                                          kwargs['apic_password'],
                                          kwargs['ssl'],
                                          verify=kwargs['secure'])
        except apic_client.rexc.SSLError as e:
            raise click.UsageError(
                "Command failed with error: %s \nTry using option "
                "'--no-secure' to skip certificate validation" % e.message)
        return f(apic, *args, **kwargs)
    return inner


def os_options(f):
    """Aggregate multiple common options into one.

    This decorator should be used by CLI commands that need an
    Openstack client."""

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

    f = click.option('--os-service-type',
                     help='Defaults to env[OS_NETWORK_SERVICE_TYPE] '
                          'or network.',
                     default='network', envvar='OS_NETWORK_SERVICE_TYPE')(f)
    f = click.option('--os-endpoint-type', envvar='OS_ENDPOINT_TYPE',
                     default='public',
                     help='Defaults to env[OS_ENDPOINT_TYPE] or public.')(f)
    f = click.option('--os-tenant-name', envvar='OS_TENANT_NAME',
                     help='Authentication tenant name, defaults to'
                          'env[OS_TENANT_NAME].')(f)
    f = click.option('--os-project-name', envvar='OS_PROJECT_NAME',
                     help='Another way to specify tenant name. '
                          'This option is mutually exclusive with '
                          '--os-tenant-name. '
                          'Defaults to env[OS_PROJECT_NAME].')(f)
    f = click.option('--os-tenant-id', envvar='OS_TENANT_ID', default='',
                     help='Authentication tenant ID, defaults to '
                          'env[OS_TENANT_ID].')(f)
    f = click.option('--insecure', default=False,
                     envvar='NEUTRONCLIENT_INSECURE',
                     help="Explicitly allow neutronclient to perform "
                          "\"insecure\" SSL (https) requests. The server's "
                          "certificate will not be verified against any "
                          "certificate authorities. This option should be "
                          "used with caution.")(f)
    f = click.option('--os-token', envvar='OS_TOKEN', default='',
                     help='Authentication token, defaults to '
                          'env[OS_TOKEN].')(f)
    f = click.option('--os-url', envvar='OS_URL', default='',
                     help='Defaults to env[OS_URL].')(f)
    f = click.option('--os-key', envvar='OS_KEY', default='',
                     help="Path of client key to use in SSL "
                          "connection. This option is not necessary "
                          "if your key is prepended to your certificate "
                          "file. Defaults to env[OS_KEY].")(f)
    f = click.option('--os-project-domain-id',
                     envvar='OS_PROJECT_DOMAIN_ID', default='',
                     help='Defaults to env[OS_PROJECT_DOMAIN_ID].')(f)

    f = click.option('--os-project-domain-name',
                     envvar='OS_PROJECT_DOMAIN_NAME', default='',
                     help='Defaults to env[OS_PROJECT_DOMAIN_NAME].')(f)

    f = click.option('--os-cert', envvar='OS_CERT', default='',
                     help="Path of certificate file to use in SSL "
                          "connection. This file can optionally be "
                          "prepended with the private key. Defaults "
                          "to env[OS_CERT].")(f)

    f = click.option('--os-cacert', envvar='OS_CACERT',
                     help="Specify a CA bundle file to use in "
                          "verifying a TLS (https) server certificate. "
                          "Defaults to env[OS_CACERT].")(f)
    f = click.option('--os-user-domain-name', envvar='OS_USER_DOMAIN_NAME',
                     default='',
                     help='OpenStack user domain name. '
                          'Defaults to env[OS_USER_DOMAIN_NAME].')(f)
    f = click.option('--os-user-domain-id', envvar='OS_USER_DOMAIN_ID',
                     default='',
                     help='OpenStack user domain ID. '
                          'Defaults to env[OS_USER_DOMAIN_ID].')(f)
    f = click.option('--os-user-id', envvar='OS_USER_ID', default='',
                     help='Authentication user ID (Env: OS_USER_ID)')(f)
    f = click.option('--http-timeout', envvar='OS_NETWORK_TIMEOUT',
                     default=None, type=click.FLOAT,
                     help='Timeout in seconds to wait for an HTTP response. '
                          'Defaults to env[OS_NETWORK_TIMEOUT] or None if not '
                          'specified.')(f)
    f = click.option('--os-cloud', envvar='OS_CLOUD', default=None,
                     help='Defaults to env[OS_CLOUD].')(f)
    return f


def apic_options(f):
    """Aggregate multiple common options into one.

    This decorator should be used by CLI commands that need an APIC client."""

    f = click.option('--apic-ip', help='APIC ip address', required=True)(f)
    f = click.option('--apic-username', help='APIC username', default=None)(f)
    f = click.option('--apic-password', help='APIC password', default=None)(f)
    f = click.option('--ssl/--no-ssl', default=True,
                     help='Whether to use SSL or not')(f)
    f = click.option('--secure/--no-secure', default=True,
                     help='Verify server certificate')(f)
    return f
