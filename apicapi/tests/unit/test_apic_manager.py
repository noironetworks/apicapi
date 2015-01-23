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
#
# @author: Henry Gessau, Cisco Systems
# @author: Ivar Lazzaro (ivar-lazzaro), Cisco Systems Inc.

import mock
from webob import exc as wexc

from apicapi import apic_manager
from apicapi.db import apic_model
from apicapi import exceptions as cexc
from apicapi.tests import base
from apicapi.tests.unit.common import test_apic_common as mocked


class TestCiscoApicManager(base.BaseTestCase,
                           mocked.ControllerMixin,
                           mocked.ConfigMixin,
                           mocked.DbModelMixin):

    def setUp(self):
        super(TestCiscoApicManager, self).setUp()
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        mocked.DbModelMixin.set_up_mocks(self)

        self.mock_apic_manager_login_responses()
        mock.patch('apicapi.apic_mapper.'
                   'APICNameMapper.app_profile').start()
        self.mgr = apic_manager.APICManager(
            apic_config=self.apic_config,
            network_config= {
                'vlan_ranges': self.vlan_ranges,
                'vni_ranges': self.vni_ranges,
                'switch_dict': self.switch_dict,
                'vpc_dict': self.vpc_dict,
                'external_network_dict': self.external_network_dict,
            }, apic_system_id=mocked.APIC_SYSTEM_ID,
            log=self.log, db=apic_model.ApicDbModel())
        self.mgr.app_profile_name = mocked.APIC_AP
        self.mocked_session.begin = self.fake_transaction
        self.session = self.mgr.apic.session
        self.assert_responses_drained()
        self.reset_reponses()
        self.addCleanup(mock.patch.stopall)
        self.mgr.use_vmm = True

    def test_mgr_session_login(self):
        login = self.mgr.apic.authentication
        self.assertEqual(login['userName'], mocked.APIC_USR)

    def test_mgr_session_logout(self):
        self.mock_response_for_post('aaaLogout')
        self.mgr.apic.logout()
        self.assert_responses_drained()
        self.assertIsNone(self.mgr.apic.authentication)

    def test_ensure_port_profile_created(self):
        switch = mocked.APIC_EXT_SWITCH
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.infraAccPortP.mo))
        self.mgr.ensure_port_profile_created_for_switch(switch)
        self.assert_responses_drained()

    def test_ensure_port_profile_created_exc(self):
        port_name = mocked.APIC_PORT
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_port_profile_created_for_switch,
                          port_name)

    def test_ensure_node_profile_created_for_switch_new(self):
        new_switch = mocked.APIC_NODE_PROF
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.infraNodeP.mo))
        self.mgr.ensure_node_profile_created_for_switch(new_switch)
        self.assert_responses_drained()

    def test_ensure_node_profile_created_for_switch_new_exc(self):
        new_switch = mocked.APIC_NODE_PROF
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_node_profile_created_for_switch,
                          new_switch)
        self.assert_responses_drained()

    def _mock_phys_dom_responses(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.physDomP.mo))

    def test_ensure_phys_domain_created_new_no_vlan_ns(self):
        dom = mocked.APIC_DOMAIN
        self._mock_phys_dom_responses()
        self.mgr.ensure_phys_domain_created_on_apic(dom)
        self.assert_responses_drained()
        new_dom = self.mgr.phys_domain_dn
        self.assertEqual(new_dom, self.mgr.apic.physDomP.dn(dom))

    def test_ensure_phys_domain_created_new_no_vlan_ns_exc(self):
        dom = mocked.APIC_DOMAIN
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_phys_domain_created_on_apic, dom)
        self.assert_responses_drained()

    def test_ensure_phys_domain_created_new_with_vlan_ns(self):
        dom = mocked.APIC_DOMAIN
        self._mock_phys_dom_responses()
        ns = 'test_vlan_ns'
        self.mgr.ensure_phys_domain_created_on_apic(dom, vlan_ns_dn=ns)
        self.assert_responses_drained()
        new_dom = self.mgr.phys_domain_dn
        self.assertEqual(new_dom, self.mgr.apic.physDomP.mo.dn(dom))

    def test_ensure_phys_domain_created_new_with_vxlan_ns(self):
        dom = mocked.APIC_DOMAIN
        # TODO(Henry): mock seg_type vxlan when vxlan is ready
        self._mock_phys_dom_responses()
        ns = 'test_vxlan_ns'
        self.mgr.ensure_phys_domain_created_on_apic(dom, vxlan_ns_dn=ns)
        self.assert_responses_drained()
        new_dom = self.mgr.phys_domain_dn
        self.assertEqual(new_dom, self.mgr.apic.physDomP.mo.dn(dom))

    def _infra_created_setup(self):
        self.mock_db_query_filterby_first_return(None)
        self.mock_db_query_distinct_return([])

    def test_ensure_infra_created_no_infra(self):
        self._infra_created_setup()
        self.mgr.switch_dict = {}
        self.mgr.ensure_infra_created_on_apic()

    def _ensure_infra_created_seq1_setup(self):
        self._infra_created_setup()
        self.mock_db_query_filterby_distinct_return([])
        self.mock_db_query_filter3_distinct_return([])

        am = 'apicapi.apic_manager.APICManager'
        np_create_for_switch = mock.patch(
            am + '.ensure_node_profile_created_for_switch').start()
        pp_create_for_switch = mock.patch(
            am + '.ensure_port_profile_created_for_switch').start()
        return np_create_for_switch, pp_create_for_switch

    def test_ensure_infra_created_seq1(self):
        np_create_for_switch, pp_create_for_switch = (
            self._ensure_infra_created_seq1_setup())
        num_links = sum([len(j)
                        for i in self.mgr.switch_dict.values()
                        for j in i.values()])

        self.mgr.ensure_infra_created_on_apic()
        self.assert_responses_drained()
        self.assertEqual(np_create_for_switch.call_count, num_links)
        self.assertEqual(pp_create_for_switch.call_count, num_links)

    def test_ensure_infra_created_seq1_exc(self):
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_infra_created_on_apic)

    def _ensure_infra_created_seq2_setup(self):
        self._infra_created_setup()
        self.mock_db_query_filterby_distinct_return([])
        self.mock_db_query_filter3_distinct_return([])

        def _profile_for_node(aswitch):
            profile = mock.Mock()
            profile.profile_id = '-'.join([aswitch, 'profile_id'])
            return profile

        self.mgr.function_profile = {'dn': 'dn'}

        am = 'apicapi.apic_manager.APICManager'
        np_create_for_switch = mock.patch(
            am + '.ensure_node_profile_created_for_switch').start()
        return np_create_for_switch

    def test_ensure_infra_created_seq2(self):
        np_create_for_switch = self._ensure_infra_created_seq2_setup()
        self.mgr.ensure_infra_created_on_apic()
        self.assert_responses_drained()

        num_links = sum([len(j)
                        for i in self.mgr.switch_dict.values()
                        for j in i.values()])
        self.assertEqual(np_create_for_switch.call_count,
                         num_links)

    def test_ensure_infra_created_seq2_exc(self):
        self.mock_db_query_filterby_all_return([])
        self.mock_db_query_filterby_distinct_return(['module'])
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_infra_created_on_apic)

    def test_ensure_context_enforced_new_ctx(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvCtx.mo))
        self.mgr.ensure_context_enforced(
            mocked.APIC_TENANT, mocked.APIC_L3CTX)
        self.assert_responses_drained()

    def test_ensure_context_enforced_pref1(self):
        self.mock_response_for_post('fvCtx')
        self.mgr.ensure_context_enforced(
            mocked.APIC_TENANT, mocked.APIC_L3CTX)
        self.assert_responses_drained()

    def test_ensure_context_enforced_pref2(self):
        self.mock_response_for_post('fvCtx', pcEnfPref='2')
        self.mgr.ensure_context_enforced(
            mocked.APIC_TENANT, mocked.APIC_L3CTX)
        self.assert_responses_drained()

    def _mock_phys_dom_prereq(self, dom):
        self._mock_phys_dom_responses()
        self.mgr.ensure_phys_domain_created_on_apic(dom)

    def test_ensure_entity_profile_created_old(self):
        ep = mocked.APIC_ATT_ENT_PROF
        self.mgr.ensure_entity_profile_created_on_apic(ep)
        self.assert_responses_drained()

    def _mock_new_entity_profile(self, exc=None):
        if not exc:
            self.mock_response_for_post(self.get_top_container(
                self.mgr.apic.infraAttEntityP.mo))
        else:
            self.mock_error_post_response(exc, code='103', text=u'Fail')

    def test_ensure_entity_profile_created_new(self):
        self._mock_phys_dom_prereq(mocked.APIC_DOMAIN)
        ep = mocked.APIC_ATT_ENT_PROF
        self._mock_new_entity_profile()
        self.mgr.ensure_entity_profile_created_on_apic(ep)
        self.assert_responses_drained()

    def test_ensure_entity_profile_created_new_exc(self):
        self._mock_phys_dom_prereq(mocked.APIC_DOMAIN)
        ep = mocked.APIC_ATT_ENT_PROF
        self._mock_new_entity_profile(exc=wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_entity_profile_created_on_apic, ep)
        self.assert_responses_drained()

    def _mock_entity_profile_preqreq(self):
        self._mock_phys_dom_prereq(mocked.APIC_DOMAIN)
        ep = mocked.APIC_ATT_ENT_PROF
        self._mock_new_entity_profile()
        self.mgr.ensure_entity_profile_created_on_apic(ep)

    def _mock_new_function_profile(self, fp):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.infraAccPortGrp.mo))

    def test_ensure_function_profile_created(self):
        fp = mocked.APIC_FUNC_PROF
        dn = self.mgr.apic.infraAttEntityP.mo.dn(fp)
        self.mgr.entity_profile = {'dn': dn}
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.infraAccPortGrp.mo))
        self.mgr.ensure_function_profile_created_on_apic(fp)
        self.assert_responses_drained()

    def test_ensure_function_profile_created_exc(self):
        fp = mocked.APIC_FUNC_PROF
        dn = self.mgr.apic.infraAttEntityP.mo.dn(fp)
        self.mgr.entity_profile = {'dn': dn}
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_function_profile_created_on_apic, fp)
        self.assert_responses_drained()

    def _mock_new_vlan_instance(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvnsVlanInstP.mo))

    def test_ensure_vlan_ns_created_new_with_encap(self):
        ns = mocked.APIC_VLAN_NAME
        self._mock_new_vlan_instance()
        new_ns = self.mgr.ensure_vlan_ns_created_on_apic(ns, '300', '399')
        self.assert_responses_drained()
        self.assertEqual(new_ns, self.mgr.apic.fvnsVlanInstP.dn(ns, 'static'))

    def test_ensure_bd_created(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvBD.mo))
        self.mgr.ensure_bd_created_on_apic('t2', 'three')
        self.assert_responses_drained()

    def test_delete_bd(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvBD.mo))
        self.mgr.delete_bd_on_apic('t1', 'bd')
        self.assert_responses_drained()

    def test_ensure_subnet_created(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvSubnet.mo))
        self.mgr.ensure_subnet_created_on_apic('t2', 'bd3', '4.4.4.4/16')
        self.assert_responses_drained()

    def test_ensure_epg_created(self):
        tenant = mocked.APIC_TENANT
        network = mocked.APIC_NETWORK
        dom = mocked.APIC_DOMAIN
        self._mock_phys_dom_prereq(dom)
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvAEPg.mo))
        new_epg = self.mgr.ensure_epg_created(tenant, network)
        self.assert_responses_drained()
        self.assertEqual(new_epg, network)

    def test_ensure_epg_created_exc(self):
        tenant = mocked.APIC_TENANT
        network = mocked.APIC_NETWORK
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_epg_created,
                          tenant, network)
        self.assert_responses_drained()

    def test_delete_epg_for_network(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvAEPg.mo))
        self.mgr.delete_epg_for_network('tenant', 'network')

    def _mock_get_switch_and_port_for_host(self):
        self.mock_db_query_filterby_distinct_return(
            mocked.FakeQuery(('swid', 'mod', 'port')))

    def test_ensure_path_created_for_port(self):
        epg = 'epg2'
        eepg = mock.Mock(return_value=epg)
        self.mgr.ensure_epg_created = eepg
        self._mock_get_switch_and_port_for_host()
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvRsPathAtt.mo))
        self.mgr.ensure_path_created_for_port('tenant', 'network', 'ubuntu2',
                                              'static')
        self.assert_responses_drained()

    def test_ensure_path_created_for_port_unknown_host(self):
        epg = mock.Mock()
        epg.epg_id = 'epg3'
        eepg = mock.Mock(return_value=epg)
        apic_manager.APICManager.ensure_epg_created = eepg
        self.mock_db_query_filterby_distinct_return(None)
        self.assertRaises(cexc.ApicHostNotConfigured,
                          self.mgr.ensure_path_created_for_port,
                          'tenant', 'network', 'cirros3', 'static')

    def test_create_tenant_filter(self):
        tenant = mocked.APIC_TENANT
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.vzEntry.mo))
        self.mgr.create_tenant_filter(tenant, apic_manager.CP_FILTER)
        self.assert_responses_drained()

    def test_create_tenant_filter_exc(self):
        tenant = mocked.APIC_TENANT
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.create_tenant_filter, tenant,
                          apic_manager.CP_FILTER)
        self.assert_responses_drained()

    def test_set_contract_for_epg_consumer(self):
        tenant = mocked.APIC_TENANT
        epg = mocked.APIC_EPG
        contract = mocked.APIC_CONTRACT
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvRsCons.mo))
        self.mgr.set_contract_for_epg(tenant, epg, contract)
        self.assert_responses_drained()

    def test_set_contract_for_epg_provider(self):
        tenant = mocked.APIC_TENANT
        epg = mocked.APIC_EPG
        contract = mocked.APIC_CONTRACT
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvRsProv.mo))
        self.mgr.set_contract_for_epg(tenant, epg, contract, provider=True)
        self.assert_responses_drained()

    def test_set_contract_for_epg_provider_exc(self):
        tenant = mocked.APIC_TENANT
        epg = mocked.APIC_EPG
        contract = mocked.APIC_CONTRACT
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.set_contract_for_epg,
                          tenant, epg, contract, provider=True)
        self.assert_responses_drained()

    def test_delete_contract_for_epg_consumer(self):
        tenant = mocked.APIC_TENANT
        epg = mocked.APIC_EPG
        contract = mocked.APIC_CONTRACT
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvRsCons.mo))
        self.mgr.delete_contract_for_epg(tenant, epg, contract)
        self.assert_responses_drained()

    def test_delete_contract_for_epg_provider(self):
        tenant = mocked.APIC_TENANT
        epg = mocked.APIC_EPG
        contract = mocked.APIC_CONTRACT
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvRsProv.mo))
        self.mgr.delete_contract_for_epg(tenant, epg, contract, provider=True)
        self.assert_responses_drained()

    def test_get_router_contract(self):
        router = mocked.APIC_ROUTER
        tenant = mocked.APIC_TENANT
        self.mock_db_query_filterby_first_return(None)
        self.mock_response_for_post('fvTenant')
        self.mgr.get_router_contract(router, owner=tenant)
        self.assert_responses_drained()
        self.assertTrue(self.mocked_session.merge.called)

    def test_get_router_contract_exc(self):
        router = mocked.APIC_ROUTER
        self.mock_response_for_get('fvCtx')
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.get_router_contract, router)

    def test_ensure_external_routed_network_created(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.l3extOut.mo))
        self.mgr.ensure_external_routed_network_created(
            mocked.APIC_NETWORK)
        self.assert_responses_drained()

    def test_ensure_logical_node_profile_created(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.l3extRsPathL3OutAtt.mo))
        self.mgr.ensure_logical_node_profile_created(
            mocked.APIC_NETWORK, mocked.APIC_EXT_SWITCH,
            mocked.APIC_EXT_MODULE, mocked.APIC_EXT_PORT,
            mocked.APIC_EXT_ENCAP, mocked.APIC_EXT_CIDR_EXPOSED)
        self.assert_responses_drained()

    def test_ensure_static_route_created(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.ipNexthopP.mo))
        self.mgr.ensure_static_route_created(mocked.APIC_NETWORK,
                                             mocked.APIC_EXT_SWITCH,
                                             mocked.APIC_EXT_GATEWAY_IP)
        self.assert_responses_drained()

    def test_ensure_external_epg_created(self):
        self.mock_response_for_get('fvCtx')
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.l3extSubnet.mo))
        self.mgr.ensure_external_epg_created(mocked.APIC_ROUTER)
        self.assert_responses_drained()

    def test_ensure_external_epg_consumed_contract(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvRsCons__Ext.mo))
        self.mgr.ensure_external_epg_consumed_contract(mocked.APIC_NETWORK,
                                                       mocked.APIC_CONTRACT)
        self.assert_responses_drained()

    def test_ensure_external_epg_provided_contract(self):
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.fvRsProv__Ext.mo))
        self.mgr.ensure_external_epg_provided_contract(mocked.APIC_NETWORK,
                                                       mocked.APIC_CONTRACT)