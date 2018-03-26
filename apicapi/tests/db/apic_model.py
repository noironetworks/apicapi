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

import mock

from apicapi.tests.db import api as db_api

HostLink = mock
HostLink.ifname = mock.Mock()
HostLink.ifname.like = mock.Mock(return_value=None)


class ApicDbModel(object):

    """DB Model to manage all APIC DB interactions."""

    def get_session(self, session=None):
        return session or db_api.get_session()

    def get_contract_for_router(self, router_id):
        """Returns the specified router's contract."""
        return self.get_session().query().filter_by(
            router_id=router_id).first()

    def write_contract_for_router(self, tenant_id, router_id):
        """Stores a new contract for the given tenant."""
        return mock.Mock()

    def update_contract_for_router(self, tenant_id, router_id):
        session = self.get_session()
        with session.begin(subtransactions=True):
            contract = session.query().filter_by(
                router_id=router_id).with_lockmode('update').first()
            if contract:
                contract.tenant_id = tenant_id
                session.merge(contract)
            else:
                self.write_contract_for_router(tenant_id, router_id)

    def delete_contract_for_router(self, router_id):
        session = self.get_session()
        with session.begin(subtransactions=True):
            try:
                session.query().filter_by(
                    router_id=router_id).delete()
            except Exception:
                return

    def add_hostlink(self, host, ifname, ifmac, swid, module, port):
        pass

    def get_hostlinks(self):
        return self.get_session().query().all()

    def get_hostlink(self, host, ifname):
        return self.get_session().query().filter_by(
            host=host, ifname=ifname).first()

    def get_hostlinks_for_host(self, host):
        return self.get_session().query().filter_by(
            host=host).all()

    def get_hostlinks_for_host_switchport(self, host, swid, module, port):
        return self.get_session().query().filter_by(
            host=host, swid=swid, module=module, port=port).all()

    def get_hostlinks_for_switchport(self, swid, module, port):
        return self.get_session().query().filter_by(
            swid=swid, module=module, port=port).all()

    def delete_hostlink(self, host, ifname):
        session = self.get_session()
        with session.begin(subtransactions=True):
            try:
                session.query().filter_by(host=host, ifname=ifname).delete()
            except Exception:
                return

    def get_switches(self):
        return self.get_session().query().distinct()

    def get_modules_for_switch(self, swid):
        return self.get_session().query().filter_by(swid=swid).distinct()

    def get_ports_for_switch_module(self, swid, module):
        return self.get_session().query().filter_by(swid=swid,
                                              module=module).distinct()

    def get_switch_and_port_for_host(self, host):
        return self.get_session().query().filter_by(host=host).distinct()

    def get_tenant_network_vlan_for_host(self, host):
        return self.get_session().query().filter_by(host=host).distinct()

    def add_apic_name(self, neutron_id, neutron_type, apic_name):
        pass

    def update_apic_name(self, neutron_id, neutron_type, apic_name):
        session = self.get_session()
        with session.begin(subtransactions=True):
            name = session.query().filter_by(
                neutron_id=neutron_id,
                neutron_type=neutron_type).with_lockmode('update').first()
            if name:
                name.apic_name = apic_name
                session.merge(name)
            else:
                self.add_apic_name(neutron_id, neutron_type, apic_name)

    def get_apic_names(self):
        return self.get_session().query().all()

    def get_apic_name(self, neutron_id, neutron_type):
        return self.get_session().query().filter_by(
            neutron_id=neutron_id, neutron_type=neutron_type).first()

    def delete_apic_name(self, neutron_id):
        session = self.get_session()
        with session.begin(subtransactions=True):
            try:
                session.query().filter_by(
                    neutron_id=neutron_id).delete()
            except Exception:
                return
