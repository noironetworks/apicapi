# Copyright (c) 2014 OpenStack Foundation
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

try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg

DEFAULT_ROOT_HELPER = ('sudo /usr/local/bin/neutron-rootwrap '
                       '/etc/neutron/rootwrap.conf')


# oslo.config limits ${var} expansion to global variables
# That is why apic_system_id as a global variable
global_opts = [
    cfg.StrOpt('apic_system_id',
               default='openstack',
               help="Prefix for APIC domain/names/profiles created"),
    cfg.StrOpt('config_file', default='etc/config_sample.ini'),
]


cfg.CONF.register_opts(global_opts)


apic_opts = [
    cfg.ListOpt('apic_hosts',
                default=[],
                help="An ordered list of host names or IP addresses of "
                     "the APIC controller(s)."),
    cfg.StrOpt('apic_username',
               help="Username for the APIC controller"),
    cfg.StrOpt('apic_password',
               help="Password for the APIC controller", secret=True),
    cfg.StrOpt('apic_name_mapping',
               default='use_name',
               help="Name mapping strategy to use: use_uuid | use_name"),
    cfg.BoolOpt('apic_use_ssl', default=True,
                help="Use SSL to connect to the APIC controller"),
    cfg.StrOpt('apic_domain_name',
               default='${apic_system_id}',
               help="Name for the domain created on APIC"),
    cfg.StrOpt('apic_app_profile_name',
               default='${apic_system_id}_app',
               help="Name for the app profile used for Openstack"),
    cfg.StrOpt('apic_vlan_ns_name',
               default='${apic_system_id}_vlan_ns',
               help="Name for the vlan namespace to be used for Openstack"),
    cfg.StrOpt('apic_node_profile',
               default='${apic_system_id}_node_profile',
               help="Name of the node profile to be created"),
    cfg.StrOpt('apic_entity_profile',
               default='${apic_system_id}_entity_profile',
               help="Name of the entity profile to be created"),
    cfg.StrOpt('apic_function_profile',
               default='${apic_system_id}_function_profile',
               help="Name of the function profile to be created"),
    cfg.StrOpt('apic_lacp_profile',
               default='${apic_system_id}_lacp_profile',
               help="Name of the LACP profile to be created"),
    cfg.ListOpt('apic_host_uplink_ports',
                default=[],
                help='The uplink ports to check for ACI connectivity'),
    cfg.ListOpt('apic_vpc_pairs',
                default=[],
                help='The switch pairs for VPC connectivity'),
    cfg.StrOpt('apic_vlan_range',
               default='2:4093',
               help="Range of VLAN's to be used for Openstack"),
    cfg.StrOpt('root_helper',
               default=DEFAULT_ROOT_HELPER,
               help="Setup root helper as rootwrap or sudo"),
    cfg.IntOpt('apic_sync_interval',
               default=0,
               help="Synchronization interval in seconds"),
    cfg.FloatOpt('apic_agent_report_interval',
                 default=30,
                 help='Interval between agent status updates (in sec)'),
    cfg.FloatOpt('apic_agent_poll_interval',
                 default=2,
                 help='Interval between agent poll for topology (in sec)'),
]


cfg.CONF.register_opts(apic_opts, "ml2_cisco_apic")


def _get_specific_config(prefix):
    """retrieve config in the format [<prefix>:<value>]."""
    conf_dict = {}
    multi_parser = cfg.MultiConfigParser()
    multi_parser.read(cfg.CONF.config_file)
    for parsed_file in multi_parser.parsed:
        for parsed_item in list(parsed_file.keys()):
            if parsed_item.startswith(prefix):
                switch, switch_id = parsed_item.split(':')
                if switch.lower() == prefix:
                    conf_dict[switch_id] = list(
                            parsed_file[parsed_item].items())
    return conf_dict


def create_switch_dictionary():
    switch_dict = {}
    conf = _get_specific_config('apic_switch')
    for switch_id in conf:
        switch_dict[switch_id] = switch_dict.get(switch_id, {})
        for host_list, port in conf[switch_id]:
            hosts = host_list.split(',')
            hosts = [a.decode('string_escape') for a in hosts]
            port = port[0]
            switch_dict[switch_id][port] = (
                switch_dict[switch_id].get(port, []) + hosts)
    return switch_dict


def create_vpc_dictionary():
    vpc_dict = {}
    for pair in cfg.CONF.ml2_cisco_apic.apic_vpc_pairs:
        pair_tuple = pair.split(':')
        if (len(pair_tuple) != 2 or
                any([not x.isdigit() for x in pair_tuple])):
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
