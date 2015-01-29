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
#
# @author: Ivar Lazzaro (ivar-lazzaro), Cisco Systems Inc.

import re
import sys

import netaddr
from oslo.config import cfg

from apicapi import apic_mapper
from apicapi import exceptions as exc

apic_opts = [
    cfg.BoolOpt('enable_aci_routing',
        default=True),
    cfg.BoolOpt('enable_arp_flooding',
        default=False),
    cfg.BoolOpt('apic_provision_infra',
        default=True),
    cfg.BoolOpt('apic_provision_hostlinks',
        default=True),
    cfg.BoolOpt('apic_multiple_hostlinks',
        default=False),
    cfg.BoolOpt('scope_names',
        default=True),
    cfg.StrOpt('apic_model',
        default='neutron.plugins.ml2.drivers.cisco.apic.apic_model'),
    cfg.BoolOpt('use_vmm', default=False),
    cfg.StrOpt('apic_vxlan_ns_name',
               default='${apic_system_id}_vxlan_ns',
               help=("Name for the vxlan namespace to be used for "
                     "Openstack")),
    cfg.StrOpt('apic_multicast_ns_name',
               default='${apic_system_id}_mcast_ns',
               help=("Name for the multicast namespace to be used for "
                     "Openstack")),
    cfg.StrOpt('apic_switch_pg_name',
               default='${apic_system_id}_sw_pg',
               help=("Name for the switch policy group to be used for "
                     "Openstack")),
    cfg.ListOpt('mcast_ranges', default=['225.1.1.1:225.1.1.128'],
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
    cfg.ListOpt('vni_ranges',
                default=[],
                help=("List of <vni_min>:<vni_max> used for vni pool "
                      "configuration"))

]

APP_PROFILE_REGEX = "[a-zA-Z0-9_.:-]+"
NOT_SET = object()


class ConfigValidator(object):
    """Configuration validator for APICAPI.

    Each method with valid_* prefix will be associated to a given configuration
    option. validate(conf, *args) will lookup the
    proper validator by name.
    """

    class RaiseUtils(object):

        def __init__(self, value, ctype):
            self.value = value
            self.ctype = ctype

        def re(self, reason):
            raise exc.InvalidConfig(value=self.value, ctype=self.ctype,
                                    reason=reason)

    def __init__(self, log):
        self.log = log

    def _validate_apic_names(self, name, ctype):
        if len(name) > apic_mapper.MAX_APIC_NAME_LENGTH:
            raise exc.InvalidConfig(
                value=name, ctype=ctype,
                reason='Apic system ID max length is ' +
                       str(apic_mapper.MAX_APIC_NAME_LENGTH))

    def _validate_ranges(self, value, util):
        # Not None
        if value is None:
            util.re("Should be a iterable")
        if value:
            # Only one range
            if len(value) > 1:
                raise util.re("Only one range definition is currently "
                              "supported")
            # Valid range
            if len(value[0].split(':')) != 2:
                raise util.re("Range should be in the form <min>:<max>")

    def validate_apic_model(self, value):
        # Verify apic model is in path and supports certain objects
        util = ConfigValidator.RaiseUtils(value, 'apic_model')
        try:
            __import__(value)
            sys.modules[value].HostLink
        except Exception as e:
            util.re(reason=e.message)

    def validate_mcast_ranges(self, value):
        util = ConfigValidator.RaiseUtils(value, 'mcast_ranges')
        self._validate_ranges(value, util)
        # Valid IPv4 address
        try:
            for x in value[0].split(':'):
                netaddr.IPAddress(x, version=4)
        except netaddr.AddrFormatError as e:
            util.re(reason=e.message)
        if (netaddr.IPAddress(value[0].split(':')[0]) >=
                netaddr.IPAddress(value[0].split(':')[1])):
            util.re("min multicast address has to be smaller than "
                    "max multicast address")

    def validate_apic_app_profile_name(self, value):
        util = ConfigValidator.RaiseUtils(value, 'apic_app_profile_name')
        match = re.match(APP_PROFILE_REGEX, value)
        if not match or match.group() != value:
            util.re("Valid regex: %s" % APP_PROFILE_REGEX)

    def validate(self, conf, *args):
        if args:
            for option in args:
                try:
                    getattr(self, 'validate_' + option)(conf.get(option))
                except AttributeError:
                    self.log.warn("There's no validation for option "
                                  "%s" % option)
        else:
            # Validate all
            for method in dir(self):
                if (callable(getattr(self, method)) and
                        method.startswith('validate_')):
                    opt = method[len('validate_'):]
                    try:
                        if conf.get(opt, NOT_SET) is NOT_SET:
                            self.log.warn(
                                "%s option is not set "
                                "in group %s" % (opt, conf._group.name))
                    except cfg.NoSuchOptError:
                        self.log.warn("No such option %s" % opt)
                    else:
                        getattr(self, method)(conf.get(opt))