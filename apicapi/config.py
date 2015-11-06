# Copyright (c) 2014 Cisco Systems Inc.
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

import re
import sys

import netaddr
try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg

from apicapi import apic_mapper
from apicapi import exceptions as exc

apic_opts = [
    cfg.BoolOpt('enable_aci_routing', default=True),
    cfg.BoolOpt('enable_optimized_dhcp', default=True),
    cfg.BoolOpt('enable_optimized_metadata', default=False),
    cfg.StrOpt('default_l2_unknown_unicast', default='proxy'),
    cfg.BoolOpt('default_arp_flooding', default=True),
    cfg.StrOpt('default_ep_move_detect', default='garp'),
    cfg.BoolOpt('default_enforce_subnet_check', default=False),
    cfg.StrOpt('default_subnet_scope', default='public'),
    cfg.BoolOpt('apic_provision_infra', default=True),
    cfg.BoolOpt('apic_provision_hostlinks', default=True),
    cfg.BoolOpt('apic_multiple_hostlinks', default=False),
    cfg.BoolOpt('scope_names', default=True),
    cfg.BoolOpt('scope_infra', default=True),
    cfg.BoolOpt('renew_names', default=False),
    cfg.StrOpt('apic_model',
               default='neutron.plugins.ml2.drivers.cisco.apic.apic_model'),
    cfg.BoolOpt('use_vmm', default=True),
    cfg.StrOpt('apic_vmm_type',
               default='OpenStack',
               help=("The vmm type of choice. Currently we only support "
                     "either OpenStack or VMware")),
    cfg.StrOpt('apic_multicast_ns_name',
               default='${apic_system_id}_mcast_ns',
               help=("Name for the multicast namespace to be used for "
                     "Openstack")),
    cfg.StrOpt('apic_switch_pg_name',
               #default='${apic_system_id}_sw_pg',
               default='openstack_sw_pg',
               help=("Name for the switch policy group to be used for "
                     "Openstack")),
    cfg.ListOpt('mcast_ranges', default=['225.2.1.1:225.2.255.255'],
                help=("Comma-separated list of "
                      "<mcast_addr_min>:<mcast_addr_max> tuples enumerating "
                      "ranges of Multicast addresses.")),
    cfg.StrOpt('openstack_user',
               default='admin',
               help=("Name of the Openstack user used by the VMM domain.")),
    cfg.StrOpt('openstack_password',
               default='somepassword', secret=True,
               help=("Password of the Openstack user used by the VMM "
                     "domain.")),
    cfg.StrOpt('multicast_address',
               default='225.1.2.3',
               help=("Multicast address used by the VMM domain.")),
    cfg.ListOpt('vlan_ranges',
                default=[],
                help=("List of <vlan_min>:<vlan_max> used for vlan pool "
                      "configuration")),
    cfg.StrOpt('shared_context_name', default=''),
    cfg.BoolOpt('verify_ssl_certificate', default=False),
    cfg.IntOpt('apic_request_timeout', default=10,
               help=("Number of seconds after which the requests to APIC "
                     "timeout in case of no response received. This is value "
                     "affects both read and connect timeout.")),
    cfg.StrOpt('private_key_file',
               help=("Filename of user's private key file to be used for "
                     "authenticating requests")),
    cfg.StrOpt('certificate_name',
               help=("Name given to user's X.509 certificate in APIC")),
    cfg.StrOpt('signature_verification_algorithm',
               help=("Algorithm used by APIC for signature verification")),
    cfg.StrOpt('signature_hash_type',
               help=("Hashing algorithm to use for calculating signature")),
    cfg.IntOpt('min_id_suffix_size',
               default=4,
               help="Minimum number of ID characters used for suffix"),
    cfg.StrOpt('vmm_controller_host', default='openstack',
               help='VMM controller IP address or DNS name, used '
                    'for OpenStack VMM'),
]

APP_PROFILE_REGEX = "[a-zA-Z0-9_.:-]+"
NOT_SET = object()


def valid_path(key, value, **kwargs):
    # Verify value is in path and supports certain objects
    try:
        __import__(value)
        sys.modules[value].HostLink
    except Exception as e:
        ConfigValidator.RaiseUtils(value, key).re(reason=e.message)


def not_null(key, value, **kwargs):
    util = ConfigValidator.RaiseUtils(value, key)
    if not value:
        util.re(reason='%s cannot be None or Empty' % key)


def valid_apic_name(key, value, **kwargs):
    util = ConfigValidator.RaiseUtils(value, key)
    not_null(key, value)
    if len(value) > apic_mapper.MAX_APIC_NAME_LENGTH:
        util.re(reason='APIC name max length is ' +
                str(apic_mapper.MAX_APIC_NAME_LENGTH))


def valid_range(key, value, **kwargs):
    # Not None
    util = ConfigValidator.RaiseUtils(value, key)
    if value is None:
        util.re("Should be a iterable")
    if value:
        if isinstance(value, list):
            # Only one range
            if len(value) > 1:
                raise util.re("Only one range definition is currently "
                              "supported")
            # Valid range
            if len(value[0].split(':')) != 2:
                raise util.re("Range should be in the form <min>:<max>")
        elif isinstance(value, str):
            if len(value.split(':')) != 2:
                raise util.re("Range should be in the form <min>:<max>")


def valid_ip(key, value, **kwargs):
    util = ConfigValidator.RaiseUtils(value, key)
    try:
        netaddr.IPAddress(value, version=4)
    except netaddr.AddrFormatError as e:
        util.re(reason=e.message)


def valid_ip_range(key, value, **kwargs):
    util = ConfigValidator.RaiseUtils(value, key)
    valid_range(key, value)
    # Valid IPv4 address
    for x in value[0].split(':'):
        valid_ip(key, x)
    if (netaddr.IPAddress(value[0].split(':')[0]) >=
            netaddr.IPAddress(value[0].split(':')[1])):
        util.re("min address has to be smaller than max address")


def valid_app_profile(key, value, **kwargs):
    valid_apic_name(key, value)
    util = ConfigValidator.RaiseUtils(value, key)
    match = re.match(APP_PROFILE_REGEX, value)
    if not match or match.group() != value:
        util.re("Valid regex: %s" % APP_PROFILE_REGEX)


def valid_name_strategy(key, value, **kwargs):
    # This is needed until the choice option is fixed upstream
    util = ConfigValidator.RaiseUtils(value, key)
    valid = ['use_name', 'use_uuid']
    if value not in valid:
        util.re("Allowed values: %s" % str(valid))


def valid_file(key, value, **kwargs):
    if value is None:
        return
    try:
        with open(value):
            pass
    except Exception as e:
        util = ConfigValidator.RaiseUtils(value, key)
        util.re("Bad file-name: %s: %s" % (value, e))


def valid_controller_host(key, value, **kwargs):
    util = ConfigValidator.RaiseUtils(value, key)
    try:
        # Depends on use_vmm
        use_vmm = kwargs['conf'].get('use_vmm')
        if not use_vmm or value:
            return
    except (KeyError, cfg.NoSuchOptError):
        pass
    util.re("%s needs to be set when use_vmm=True" % key)


class ConfigValidator(object):
    """Configuration validator for APICAPI.

    Each method with valid_* prefix will be associated to a given configuration
    option. validate(conf, *args) will lookup the
    proper validator by name.
    """

    validators = {
        'apic_model': [valid_path],
        'apic_multicast_ns_name': [valid_apic_name],
        'apic_switch_pg_name': [valid_apic_name],
        'openstack_user': [not_null],
        'multicast_address': [valid_ip],
        'vlan_ranges': [valid_range],
        'mcast_ranges': [valid_ip_range],
        'apic_name_mapping': [valid_name_strategy],
        'apic_domain_name': [valid_apic_name],
        'apic_app_profile_name': [valid_app_profile],
        'apic_vlan_ns_name': [valid_apic_name],
        'apic_node_profile': [valid_apic_name],
        'apic_entity_profile': [valid_apic_name],
        'apic_function_profile': [valid_apic_name],
        'apic_lacp_profile': [valid_apic_name],
        'apic_vlan_range': [valid_range],
        'private_key_file': [valid_file],
        'apic_vmm_type': [valid_apic_name],
        'vmm_controller_host': [valid_controller_host],
    }

    class RaiseUtils(object):

        def __init__(self, value, ctype):
            self.value = value
            self.ctype = ctype

        def re(self, reason):
            raise exc.InvalidConfig(value=self.value, ctype=self.ctype,
                                    reason=reason)

    def __init__(self, log):
        self.log = log

    def _validate(self, key, value, conf):
        for x in self.validators[key]:
            x(key, value, conf=conf)

    def validate(self, conf, *args):
        if args:
            for opt in args:
                try:
                    self._validate(opt, conf.get(opt), conf)
                except KeyError:
                    self.log.warn("There's no validation for option "
                                  "%s" % opt)
                except cfg.NoSuchOptError:
                    self.log.warn("Option %s is not configured" % opt)
        else:
            # Validate all known options
            for opt in self.validators:
                try:
                    value = conf.get(opt)
                    self._validate(opt, value, conf)
                except cfg.NoSuchOptError:
                    pass
