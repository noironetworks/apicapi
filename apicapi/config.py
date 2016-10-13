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

from apicapi import apic_domain
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
               default=apic_domain.APIC_VMM_TYPE_OPENSTACK,
               help=("The vmm type of choice. Currently we only support "
                     "either OpenStack or VMware")),
    cfg.StrOpt('apic_multicast_ns_name',
               default='${apic_system_id}_mcast_ns',
               help=("Name for the multicast namespace to be used for "
                     "Openstack")),
    cfg.StrOpt('apic_switch_pg_name',
               # default='${apic_system_id}_sw_pg',
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
    cfg.StrOpt('apic_external_routed_domain_name',
               default='${apic_system_id}_l3ext',
               help=("Name of external routed domain to be created on APIC")),
    cfg.StrOpt('apic_external_routed_entity_profile',
               default='${apic_system_id}_l3ext_entity_profile',
               help=("Name of the entity profile to be created for "
                     "external routed domain")),
    cfg.StrOpt('apic_external_routed_function_profile',
               default='${apic_system_id}_l3ext_function_profile',
               help=("Name of the function profile to be created for "
                     "external routed domain")),
    cfg.StrOpt('encap_mode',
               help=('Encapsulation to use (vlan, vxlan etc) with APIC '
                     'domain. If unspecified, encap is inferred from values '
                     'of other options')),
    cfg.BoolOpt('per_tenant_nat_epg', default=False,
                help=('Whether NAT-ed endpoints should be segregated by '
                      'tenants')),
]


# These options are moved from ML2 to APICAPI and are relevant to apicapi.
# TODO(ivar): remove VMM specific option for multiple VMM implementation
apic_opts_from_ml2 = [
    cfg.ListOpt('apic_hosts',
                default=[],
                help=("An ordered list of host names or IP addresses of "
                      "the APIC controller(s).")),
    cfg.StrOpt('apic_username',
               help=("Username for the APIC controller")),
    cfg.StrOpt('apic_password',
               help=("Password for the APIC controller"), secret=True),
    cfg.StrOpt('apic_name_mapping',
               default='use_uuid',
               help=("Name mapping strategy to use: use_uuid | use_name")),
    cfg.BoolOpt('apic_use_ssl',
                default=True,
                help=("Use SSL to connect to the APIC controller")),
    cfg.StrOpt('apic_domain_name',
               default='${apic_system_id}',
               help=("Name for the domain created on APIC")),
    cfg.StrOpt('apic_app_profile_name',
               default='${apic_system_id}_app',
               help=("Name for the app profile used for Openstack")),
    cfg.StrOpt('apic_vlan_ns_name',
               default='${apic_system_id}_vlan_ns',
               help=("Name for the vlan namespace to be used for Openstack")),
    cfg.StrOpt('apic_node_profile',
               default='${apic_system_id}_node_profile',
               help=("Name of the node profile to be created")),
    cfg.StrOpt('apic_entity_profile',
               default='${apic_system_id}_entity_profile',
               help=("Name of the entity profile to be created")),
    cfg.StrOpt('apic_function_profile',
               default='${apic_system_id}_function_profile',
               help=("Name of the function profile to be created")),
    cfg.StrOpt('apic_lacp_profile',
               default='${apic_system_id}_lacp_profile',
               help=("Name of the LACP profile to be created")),
    cfg.ListOpt('apic_host_uplink_ports',
                default=[],
                help=('The uplink ports to check for ACI connectivity')),
    cfg.ListOpt('apic_vpc_pairs',
                default=[],
                help=('The switch pairs for VPC connectivity')),
    cfg.StrOpt('apic_vlan_range',
               default='2:4093',
               help=("Range of VLAN's to be used for Openstack")),
]


cfg.CONF.register_opts(apic_opts + apic_opts_from_ml2, "apic")

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


def valid_encap_mode(key, value, **kwargs):
    util = ConfigValidator.RaiseUtils(value, key)
    valid = ['vlan', 'vxlan']
    if value and (value not in valid):
        util.re("Allowed values: %s" % str(valid))


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
        'apic_external_routed_domain_name': [valid_apic_name],
        'apic_external_routed_entity_profile': [valid_apic_name],
        'apic_external_routed_function_profile': [valid_apic_name],
        'encap_mode': [valid_encap_mode],
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


# With apic specific config split from apic_ml2, creating the switch
# dictionaries should be done by apicapi itself
def _get_specific_config(prefix):
    """retrieve config in the format [<prefix>:<value>]."""
    conf_dict = {}
    multi_parser = cfg.MultiConfigParser()
    multi_parser.read(cfg.CONF.config_file)
    for parsed_file in multi_parser.parsed:
        for parsed_item in parsed_file.keys():
            if parsed_item.startswith(prefix):
                found_prefix, value = parsed_item.split(':')
                if found_prefix.lower() == prefix.lower():
                    conf_dict[value.strip()] = parsed_file[parsed_item].items()
    return conf_dict


def create_switch_dictionary():
    switch_dict = {}
    conf = _get_specific_config('apic_switch')
    for switch_id in conf:
        switch_dict[switch_id] = switch_dict.get(switch_id, {})
        for host_list, port in conf[switch_id]:
            hosts = host_list.split(',')
            port = port[0]
            switch_dict[switch_id][port] = (
                switch_dict[switch_id].get(port, []) + hosts)
    return switch_dict


def create_vpc_dictionary(apic_config):
    vpc_dict = {}
    for pair in apic_config.apic_vpc_pairs:
        pair_tuple = pair.split(':')
        if (len(pair_tuple) != 2 or
                any(map(lambda x: not x.isdigit(), pair_tuple))):
            # Validation error, ignore this item
            continue
        vpc_dict[pair_tuple[0]] = pair_tuple[1]
        vpc_dict[pair_tuple[1]] = pair_tuple[0]
    return vpc_dict


def create_external_network_dictionary():
    router_dict = {}
    conf = _get_specific_config('apic_external_network')
    for net_id in conf:
        router_dict[net_id] = router_dict.get(net_id, {})
        for key, value in conf[net_id]:
            router_dict[net_id][key] = value[0] if value else None

    return router_dict


def _create_apic_dom_dictionary(prefix):
    dom_dict = {}
    conf = _get_specific_config(prefix)
    for dom in conf:
        dom_dict.setdefault(dom, {})
        for key, value in conf[dom]:
            if value:
                dom_dict[dom][key] = value[0]

    return dom_dict


def create_physdom_dictionary():
    return _create_apic_dom_dictionary('apic_physdom')


def create_vmdom_dictionary():
    return _create_apic_dom_dictionary('apic_vmdom')


def create_physical_network_dict():
    phy_net_dict = {}
    conf = _get_specific_config('apic_physical_network')
    for segment in conf:
        seg_kv = phy_net_dict.setdefault(segment, {'hosts': set()})
        for key, value in conf[segment]:
            if key == 'hosts':
                host_list = value[0] if value else []
                host_list = [h.strip() for h in host_list.split(',')]
                seg_kv['hosts'] = set([h for h in host_list if h])
            else:
                seg_kv[key] = value[0] if value else None
    return phy_net_dict
