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


class NoopDbModel(object):

    def get_contract_for_router(self, router_id):
        return None

    def write_contract_for_router(self, tenant_id, router_id):
        pass

    def update_contract_for_router(self, tenant_id, router_id):
        pass

    def delete_contract_for_router(self, router_id):
        pass

    def add_hostlink(self, host, ifname, ifmac, swid, module, port):
        pass

    def get_hostlinks(self):
        return []

    def get_hostlink(self, host, ifname):
        pass

    def get_hostlinks_for_host(self, host):
        return []

    def get_hostlinks_for_host_switchport(self, host, swid, module, port):
        return []

    def get_hostlinks_for_switchport(self, swid, module, port):
        return []

    def delete_hostlink(self, host, ifname):
        pass

    def get_switches(self):
        return []

    def get_modules_for_switch(self, swid):
        return []

    def get_ports_for_switch_module(self, swid, module):
        return []

    def get_switch_and_port_for_host(self, host):
        return []

    def get_tenant_network_vlan_for_host(self, host):
        return []

    def add_apic_name(self, neutron_id, neutron_type, apic_name):
        pass

    def update_apic_name(self, neutron_id, neutron_type, apic_name):
        pass

    def get_apic_names(self):
        return []

    def get_apic_name(self, neutron_id, neutron_type):
        pass

    def delete_apic_name(self, neutron_id):
        pass
