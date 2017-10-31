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

import copy
import mock
from webob import exc as wexc

from apicapi import apic_domain
from apicapi import apic_manager
from apicapi import config
from apicapi import exceptions as cexc
from apicapi.tests import base
from apicapi.tests.db import apic_model
from apicapi.tests.unit.common import test_apic_common as mocked


class FakeConf(dict):
    def __getattr__(self, attr):
        return self[attr]

    def __setattr__(self, key, value):
        self[key] = value


class TestCiscoApicManager(base.BaseTestCase,
                           mocked.ControllerMixin,
                           mocked.ConfigMixin,
                           mocked.DbModelMixin):

    def setUp(self, config_group='ml2_cisco_apic'):
        self.config_group = config_group
        if config_group == 'ml2_cisco_apic':
            self.clear_config('apic_username', 'apic')
        super(TestCiscoApicManager, self).setUp()
        self._initialize_manager()

    def _initialize_manager(self, vmm=False, phys_domains=None,
                            vmm_domains=None, set_network_config=True):
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        mocked.DbModelMixin.set_up_mocks(self)

        self.mock_apic_manager_login_responses()
        mock.patch('apicapi.apic_mapper.'
                   'APICNameMapper.app_profile').start()
        self.apic_config._conf.register_opts(
            config.apic_opts, self.apic_config._group.name)
        self.override_config('apic_model', 'apicapi.tests.db.apic_model',
                             self.config_group)
        self.override_config('vmm_controller_host', 'somename',
                             self.config_group)
        self.override_config('use_vmm', bool(vmm or vmm_domains),
                             self.config_group)
        self.override_config('apic_switch_pg_name', mocked.APIC_SW_PG_NAME,
                             self.config_group)
        domain = {mocked.APIC_DOMAIN: {}}
        config.create_physdom_dictionary = mock.Mock(
            return_value=phys_domains or {})
        config.create_vmdom_dictionary = mock.Mock(
            return_value=vmm_domains or {})
        if not phys_domains and not vmm_domains:
            if vmm:
                config.create_vmdom_dictionary = mock.Mock(
                    return_value=domain)
            else:
                config.create_physdom_dictionary = mock.Mock(
                    return_value=domain)

        network_config = {
            'vlan_ranges': self.vlan_ranges,
            'switch_dict': self.switch_dict,
            'vpc_dict': self.vpc_dict,
            'external_network_dict': self.external_network_dict,
        } if set_network_config else {}
        self.mgr = apic_manager.APICManager(
            apic_config=self.apic_config,
            network_config=network_config,
            apic_system_id=mocked.APIC_SYSTEM_ID,
            log=self.log, db=apic_model.ApicDbModel())
        self.mgr.apic.infraAccNodePGrp.get = mock.Mock(return_value='not-None')
        self.mgr.app_profile_name = mocked.APIC_AP
        self.mocked_session.begin = self.fake_transaction
        self.session = self.mgr.apic.session
        self.assert_responses_drained()
        self.reset_reponses()
        self.addCleanup(mock.patch.stopall)

    def _get_ext_switches_to_provision(self):
        return set([x['switch'] for x in self.external_network_dict.values()
                    if x.get('switch')])

    def _check_call_list(self, expected, observed, check_all=True):
        for call in expected:
            self.assertTrue(call in observed,
                            msg='Call not found, expected:\n%s\nobserved:'
                                '\n%s' % (str(call), str(observed)))
            observed.remove(call)
        if check_all:
            self.assertFalse(
                len(observed),
                msg='There are more calls than expected: %s' % str(observed))

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
        self.mgr.domains[0]._ensure_phys_domain_created_on_apic(dom)
        self.assert_responses_drained()
        new_dom = self.mgr.domains[0].dn
        self.assertEqual(new_dom, self.mgr.apic.physDomP.dn(dom))

    def test_ensure_phys_domain_created_new_no_vlan_ns_exc(self):
        dom = mocked.APIC_DOMAIN
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(
            cexc.ApicResponseNotOk,
            self.mgr.domains[0]._ensure_phys_domain_created_on_apic, dom)
        self.assert_responses_drained()

    def test_ensure_phys_domain_created_new_with_vlan_ns(self):
        dom = mocked.APIC_DOMAIN
        self._mock_phys_dom_responses()
        ns = 'test_vlan_ns'
        self.mgr.domains[0]._ensure_phys_domain_created_on_apic(dom,
                                                                vlan_ns_dn=ns)
        self.assert_responses_drained()
        new_dom = self.mgr.domains[0].dn
        self.assertEqual(new_dom, self.mgr.apic.physDomP.mo.dn(dom))

    def test_ensure_l3ext_domain_created(self):
        dom = mocked.APIC_L3EXT_DOMAIN
        self.mock_response_for_post(self.get_top_container(
            self.mgr.apic.l3extDomP.mo))
        self.mgr.ensure_l3ext_domain_created_on_apic(dom)
        self.assert_responses_drained()
        new_dom = self.mgr.l3ext_domain_dn
        self.assertEqual(new_dom, self.mgr.apic.l3extDomP.mo.dn(dom))

    def _infra_created_setup(self):
        self.mock_db_query_filterby_first_return(None)
        self.mock_db_query_distinct_return([])

    def test_ensure_infra_created_no_infra(self):
        self._infra_created_setup()
        self.mgr.switch_dict = {}
        self.mgr.ext_net_dict = {}
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

    def test_ensure_host_links_created_vpc(self):
        np_create_for_switch, pp_create_for_switch = (
            self._ensure_infra_created_seq1_setup())

        self.mgr.provision_hostlinks = False
        self.mgr.switch_dict = {
            '201': {'vpc-1-34/bundle-201-1-34-and-202-1-34': ['ubuntu1|eth1'],
                    'vpc-1-33/bundle-201-1-33-and-202-1-33': ['ubuntu2|eth2'],
                    'pod_id': '3'},
            '202': {'vpc-1-34/bundle-201-1-34-and-202-1-34': ['ubuntu1|eth3'],
                    'vpc-1-33/bundle-201-1-33-and-202-1-33': ['ubuntu2|eth4'],
                    'pod_id': '3'}
        }
        self.mgr.db.add_hostlink = mock.Mock()
        self.mgr.ensure_infra_created_on_apic()
        self.assert_responses_drained()
        exp_calls = [
            mock.call(
                'ubuntu1', 'eth1', None, '201', 'vpc-1-34',
                'bundle-201-1-34-and-202-1-34',
                'topology/pod-3/protpaths-201-202/pathep-'
                '[bundle-201-1-34-and-202-1-34]',
                '3', from_config=True),
            mock.call(
                'ubuntu2', 'eth2', None, '201', 'vpc-1-33',
                'bundle-201-1-33-and-202-1-33',
                'topology/pod-3/protpaths-201-202/pathep-'
                '[bundle-201-1-33-and-202-1-33]',
                '3', from_config=True),
            mock.call(
                'ubuntu1', 'eth3', None, '202', 'vpc-1-34',
                'bundle-201-1-34-and-202-1-34',
                'topology/pod-3/protpaths-201-202/pathep-'
                '[bundle-201-1-34-and-202-1-34]',
                '3', from_config=True),
            mock.call(
                'ubuntu2', 'eth4', None, '202', 'vpc-1-33',
                'bundle-201-1-33-and-202-1-33',
                'topology/pod-3/protpaths-201-202/pathep-'
                '[bundle-201-1-33-and-202-1-33]',
                '3', from_config=True)]
        self._check_call_list(exp_calls,
            self.mgr.db.add_hostlink.call_args_list)

    def test_ensure_infra_created_seq1(self):
        np_create_for_switch, pp_create_for_switch = (
            self._ensure_infra_created_seq1_setup())

        switch_dict_copy = copy.deepcopy(self.mgr.switch_dict)
        for value in switch_dict_copy.values():
            for key in value.keys():
                if key == 'pod_id':
                    del value[key]

        num_links = sum([len(j)
                        for i in switch_dict_copy.values()
                        for j in i.values()])
        num_ext_switch = len(self._get_ext_switches_to_provision())

        self.mgr.db.add_hostlink = mock.Mock()
        self.mgr.ensure_infra_created_on_apic()
        self.assert_responses_drained()
        self.assertEqual(np_create_for_switch.call_count,
            num_links + num_ext_switch)
        self.assertEqual(pp_create_for_switch.call_count,
            num_links + num_ext_switch)
        exp_calls = [
            mock.call('ubuntu1', 'static', None, '101', '3', '11',
                      'topology/pod-1/paths-101/pathep-[eth3/11]', '1',
                      from_config=True),
            mock.call('ubuntu2', 'static', None, '101', '3', '11',
                      'topology/pod-1/paths-101/pathep-[eth3/11]', '1',
                      from_config=True),
            mock.call('rhel01', 'eth1', None, '102', '4', '21',
                      'topology/pod-2/paths-102/pathep-[eth4/21]', '2',
                      from_config=True),
            mock.call('rhel02', 'eth2', None, '102', '4', '21',
                      'topology/pod-2/paths-102/pathep-[eth4/21]', '2',
                      from_config=True),
            mock.call('rhel03', 'eth3', None, '102', '1', '4/22',
                      'topology/pod-2/paths-102/pathep-[eth1/4/22]', '2',
                      from_config=True)]
        self._check_call_list(exp_calls,
            self.mgr.db.add_hostlink.call_args_list)

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

        switch_dict_copy = copy.deepcopy(self.mgr.switch_dict)
        for value in switch_dict_copy.values():
            for key in value.keys():
                if key == 'pod_id':
                    del value[key]

        num_links = sum([len(j)
                        for i in switch_dict_copy.values()
                        for j in i.values()])
        num_ext_switch = len(self._get_ext_switches_to_provision())
        self.assertEqual(np_create_for_switch.call_count,
                         num_links + num_ext_switch)

    def test_ensure_infra_created_seq2_exc(self):
        self.mock_db_query_filterby_all_return([])
        self.mock_db_query_filterby_distinct_return(['module'])
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_infra_created_on_apic)

    def test_good_vmware_vmm_domain_inside_ensure_infra_created_on_apic(self):
        np_create_for_switch, pp_create_for_switch = (
            self._ensure_infra_created_seq1_setup())
        self.mgr.apic_vmm_type = 'VMware'
        self.override_config('apic_domain_name', 'good_name',
                             self.config_group)
        self.mock_response_for_get('vmmDomP', dn="good_dn")
        self.mgr.ensure_infra_created_on_apic()

    def test_nonexist_vmware_vmm_domain_inside_ensure_infra_created_on_apic(
            self):
        self.override_config('apic_vmm_type', 'VMware', self.config_group)
        self._initialize_manager(True)
        self.override_config('apic_domain_name', 'bad_name', self.config_group)
        self.mock_response_for_get('vmmDomP')
        self.assertRaises(cexc.ApicVmwareVmmDomainNotConfigured,
                          self.mgr.ensure_infra_created_on_apic)

    def test_wrong_vmm_type_inside_ensure_infra_created_on_apic(self):
        self.override_config('apic_vmm_type', 'wrong-type', self.config_group)
        self._initialize_manager(True)
        self.assertRaises(cexc.ApicVmmTypeNotSupported,
                          self.mgr.ensure_infra_created_on_apic)

    def test_ensure_infra_created_l3ext_domain(self):
        self._ensure_infra_created_seq1_setup()

        mgr = self.mgr
        mgr.ensure_l3ext_domain_created_on_apic = mock.Mock()
        mgr.ensure_entity_profile_created_on_apic = mock.Mock()
        mgr.ensure_function_profile_created_on_apic = mock.Mock()
        mgr.ensure_access_port_selector_created = mock.Mock()

        mgr.ensure_infra_created_on_apic()
        mgr.ensure_l3ext_domain_created_on_apic.assert_called_once_with(
            mocked.APIC_L3EXT_DOMAIN)
        mgr.ensure_entity_profile_created_on_apic.assert_called_with(
            mocked.APIC_L3EXT_ATT_ENT_PROF,
            domain_dn=mgr.apic.l3extDomP.mo.dn(mocked.APIC_L3EXT_DOMAIN),
            enable_infra_vlan=False, incl_vmware_vmm=False)
        mgr.ensure_function_profile_created_on_apic.assert_called_with(
            mocked.APIC_L3EXT_FUNC_PROF,
            entity_profile_dn=mgr.apic.infraAttEntityP.mo.dn(
                mocked.APIC_L3EXT_ATT_ENT_PROF))
        mgr.ensure_access_port_selector_created.assert_called_once_with(
            mocked.APIC_EXT_SWITCH, mocked.APIC_EXT_MODULE,
            mocked.APIC_EXT_PORT,
            mgr.apic.infraAccPortGrp.mo.dn(mocked.APIC_L3EXT_FUNC_PROF))

    def test_no_provision_infra(self):
        self._initialize_manager(
            phys_domains={mocked.APIC_DOMAIN: {}},
            vmm_domains={mocked.APIC_DOMAIN + '1': {
                            'apic_vmm_type': 'OpenStack'},
                         mocked.APIC_DOMAIN + '2': {
                            'apic_vmm_type': 'VMware'}})
        self.mgr.provision_infra = False
        self.mgr.apic.infraAttEntityP.create = mock.Mock()
        self.mgr.apic.infraProvAcc.create = mock.Mock()

        with mock.patch(
            'apicapi.apic_domain.VmDomain._ensure_vmm_domain_created_on_apic'):
            self.mock_response_for_get('vmmDomP', dn="/uni/vmware")
            self.mock_response_for_get('infraAttEntityP')
            self.mock_db_query_filterby_distinct_return([('switch', 'ifname')])

            self.mgr.ensure_infra_created_on_apic()
            advd = apic_domain.VmDomain
            self.assertEqual(1,
                advd._ensure_vmm_domain_created_on_apic.call_count)
            self.assertFalse(self.mgr.apic.infraAttEntityP.create.called)
            self.assertFalse(self.mgr.apic.infraProvAcc.create.called)

    def test_no_provision_infra_setup_aep_for_domains(self):
        self._initialize_manager(
            vmm_domains={mocked.APIC_DOMAIN: {
                            'apic_vmm_type': 'OpenStack'}})
        self.mgr.provision_infra = False
        self.mgr.apic.infraRsDomP.create = mock.Mock()
        with mock.patch(
            'apicapi.apic_domain.VmDomain._ensure_vmm_domain_created_on_apic'):
            self.mock_db_query_filterby_distinct_return([('switch', 'ifname')])

            self.mock_response_for_get('infraAttEntityP', name="good_aep")
            self.mgr.ensure_infra_created_on_apic()
            self.mgr.apic.infraRsDomP.create.assert_called_once_with(
                mocked.APIC_ATT_ENT_PROF,
                self.mgr.apic.vmmDomP.mo.dn('OpenStack', mocked.APIC_DOMAIN),
                transaction=mock.ANY)

            # try again but this time AEP doesn't exist
            self.mgr.apic.infraRsDomP.create.reset_mock()
            self.mock_response_for_get('infraAttEntityP')
            self.mgr.ensure_infra_created_on_apic()
            self.assertFalse(self.mgr.apic.infraRsDomP.create.called)

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
        self.mgr.domains[0]._ensure_phys_domain_created_on_apic(dom)

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
        ft = [False, True]
        for x in ft:
            # Initialize manager based on domain type
            self._initialize_manager(x)
            new_ns = self.mgr.domains[0]._ensure_vlan_ns_created_on_apic(
                ns, '300', '399')
            self.assert_responses_drained()
            self.assertEqual(new_ns, self.mgr.apic.fvnsVlanInstP.dn(
                ns, 'static' if not x else 'dynamic'))

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
        self.mgr.ensure_subnet_created_on_apic('t3', 'bd4', '4.4.4.4/16',
                                               scope='public')
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

    def test_ensure_path_deleted_for_port_not_called(self):
        self.mgr.apic.fvRsPathAtt.delete = mock.Mock()
        self.mgr.db.get_switch_and_port_for_host = mock.Mock(return_value=None)
        self.mgr.ensure_path_deleted_for_port('tenant', 'network', 'ubuntu2')
        self.assertEqual(0, self.mgr.apic.fvRsPathAtt.delete.call_count)

    def test_ensure_path_deleted_for_port(self):
        self.mgr.apic.fvRsPathAtt.delete = mock.Mock()
        self._mock_get_switch_and_port_for_host()
        self.mgr.ensure_path_deleted_for_port('tenant', 'network', 'ubuntu2')
        self.mgr.apic.fvRsPathAtt.delete.assert_called_once_with(
            'tenant', self.mgr.app_profile_name, 'network',
            apic_manager.PORT_DN_PATH % ('1', 'swid', 'mod', 'port'),
            transaction=mock.ANY)

    def test_ensure_path_deleted_for_port_host_config(self):
        self.mgr.apic.fvRsPathAtt.delete = mock.Mock()
        self.mgr.ensure_path_deleted_for_port(
            'tenant', 'network', 'ubuntu2',
            host_config=mocked.FakeQuery(('switch', 'module', 'port')))
        self.mgr.apic.fvRsPathAtt.delete.assert_called_once_with(
            'tenant', self.mgr.app_profile_name, 'network',
            apic_manager.PORT_DN_PATH % ('1', 'switch', 'module', 'port'),
            transaction=mock.ANY)

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

    def test_segment_config(self):
        vlan_ranges = ['200:299']
        self.override_config('vlan_ranges', vlan_ranges, self.config_group)
        self._initialize_manager()
        self.assertEqual(self.mgr.vlan_ranges, vlan_ranges)
        self.override_config('vlan_ranges', [], self.config_group)
        self._initialize_manager()
        self.assertEqual(self.mgr.vlan_ranges,
                         [':'.join(self.vlan_ranges[1].split(':')[-2:])])
        self.assertEqual(self.mgr.domains[0].vlan_ranges,
                         [':'.join(self.vlan_ranges[1].split(':')[-2:])])

    def test_auth_url(self):
        mapper = self.mgr._apic_mapper
        conf = FakeConf()
        correct_url = 'http://controller:5000/'
        test_inputs = ['http://controller:5000/v2.0/',
                       'http://controller:5000/v2.0////',
                       'http://controller:5000/v2.0',
                       'http://controller:5000',
                       'http://controller:5000/',
                       None]
        conf.auth_uri = 'http://controller:5000/v2.0'
        conf.auth_protocol = 'http'
        conf.auth_host = 'controller'
        conf.auth_port = '5000'
        conf.admin_user = 'user'
        conf.admin_password = 'password'
        conf.admin_tenant_name = 'tenant'

        for input in test_inputs:
            conf.auth_uri = input
            url = mapper.get_key_password_params(conf)
            self.assertEqual((correct_url, 'user', 'password', 'tenant'), url)

        # Test with suffix
        for input in test_inputs:
            conf.auth_uri = input
            url = mapper.get_key_password_params(conf, suffix='/v2.0')
            self.assertEqual((correct_url + 'v2.0/', 'user', 'password',
                              'tenant'), url)

    def test_timeout_set(self):
        client = self.mgr.apic
        self.assertEqual(client.request_timeout, 10)

    def test_grow_if_needed(self):
        mapper = self.mgr._apic_mapper
        test_values = set([('network', 'onename'),
                           ('network', 'onename_12345'),
                           ('router', 'onename_12345678'),
                           ('router', 'onename_123456789'),
                           ('router', 'onename_1234567890'),
                           ])

        def get_filtered_apic_names(neutron_type=None, apic_name=None):
            return (neutron_type, apic_name) in test_values
        mapper.db = mock.Mock()
        mapper.db.get_filtered_apic_names = get_filtered_apic_names

        test_id = '1234567890'
        test_result = 'differentname'
        # Unexisting name gets returned as is
        self.assertEqual(
            'differentname', mapper._grow_id_if_needed(test_id, 'network',
                                                       test_result, start=5))

        test_result = 'onename_12345'
        # One character is added to clashing name
        self.assertEqual(
            'onename_123456', mapper._grow_id_if_needed(test_id, 'network',
                                                        test_result, start=5))
        # Clashing name of different type is returned as is
        self.assertEqual(
            'onename_12345', mapper._grow_id_if_needed(test_id, 'router',
                                                       test_result, start=5))
        # Give up when the whole id is consumed
        test_result = 'onename_12345678'
        self.assertEqual(
            'onename_1234567890', mapper._grow_id_if_needed(
                test_id, 'router', test_result, start=8))

    def test_bd_enforce_subnet_check(self):
        self.mgr.apic.fvBD.create = mock.Mock()
        self.mgr.default_enforce_subnet_check = True
        self.mgr.ensure_bd_created_on_apic('test', 'test')
        self.mgr.apic.fvBD.create.assert_called_once_with(
                'test', 'test',
                arpFlood=mock.ANY,
                unkMacUcastAct=mock.ANY,
                unicastRoute=mock.ANY,
                epMoveDetectMode=mock.ANY,
                limitIpLearnToSubnets='yes',
                transaction=mock.ANY)
        # verifies explicit arg overrides the ip check
        self.mgr.apic.fvBD.create.reset_mock()
        self.mgr.ensure_bd_created_on_apic('test', 'test',
                                           enforce_subnet_check=False)
        self.mgr.apic.fvBD.create.assert_called_once_with(
                'test', 'test',
                arpFlood=mock.ANY,
                unkMacUcastAct=mock.ANY,
                unicastRoute=mock.ANY,
                epMoveDetectMode=mock.ANY,
                limitIpLearnToSubnets='no',
                transaction=mock.ANY)

    def test_sw_pg_name_scoped(self):
        self._initialize_manager()
        self.assertEqual(
            '_' + mocked.APIC_SYSTEM_ID + '_' + mocked.APIC_SW_PG_NAME,
            self.mgr.sw_pg_name)
        self.assertEqual(
            self.mgr.apic.infraAccNodePGrp.dn('_' + mocked.APIC_SYSTEM_ID +
                                              '_' + mocked.APIC_SW_PG_NAME),
            self.mgr.switch_pg_dn)

    def test_sw_pg_name_unscoped(self):
        self._initialize_manager()
        self.mgr.apic.infraAccNodePGrp.get = mock.Mock(return_value=None)
        self.assertEqual(mocked.APIC_SW_PG_NAME, self.mgr.sw_pg_name)
        self.assertEqual(
            self.mgr.apic.infraAccNodePGrp.dn(mocked.APIC_SW_PG_NAME),
            self.mgr.switch_pg_dn)

    def test_use_vmm(self):
        self._initialize_manager()
        self.assertFalse(self.mgr.use_vmm)
        self._initialize_manager(vmm_domains={mocked.APIC_DOMAIN: {}})
        self.assertTrue(self.mgr.use_vmm)

    def test_vmware_vmm_creation(self):
        self.override_config('apic_vmm_type', 'vmware', self.config_group)
        self._initialize_manager(vmm=True)

        # this is because in retrieve_domains(), it will insert
        # the extra openStack vmm domain
        self.assertEqual(2, len(self.mgr.domains))

        self.mgr.domains[0]._ensure_vmm_domain_created_on_apic = mock.Mock()
        self.mgr.domains[1]._ensure_vmm_domain_created_on_apic = mock.Mock()
        self.mgr.db.get_switches = mock.Mock(return_value=[])
        self.mgr.db.get_modules_for_switch = mock.Mock(return_value=[])
        self.mgr.db.get_switch_and_port_for_host = mock.Mock(return_value=[])
        self.mock_response_for_get('vmmDomP', dn='good_dn')

        self.mgr.ensure_infra_created_on_apic()
        (self.assertFalse(self.mgr.domains[0].
            _ensure_vmm_domain_created_on_apic.called))
        (self.mgr.domains[1]._ensure_vmm_domain_created_on_apic.
            assert_called_once_with(apic_domain.APIC_VMM_TYPE_OPENSTACK,
                                    mocked.APIC_SYSTEM_ID,
                                    mock.ANY, mock.ANY, mock.ANY,
                                    vlan_ns_dn=mock.ANY))
        self.assertEqual(
            set([mocked.APIC_DOMAIN, mocked.APIC_SYSTEM_ID]),
            set([self.mgr.domains[0].name, self.mgr.domains[1].name]))

    def _mock_db_calls(self, mgr):
        mgr.db.get_switches = mock.Mock(return_value=[])
        mgr.db.get_modules_for_switch = mock.Mock(return_value=[])
        mgr.db.get_switch_and_port_for_host = mock.Mock(return_value=[])

    def _test_encap_mode(self, mode):
        if mode:
            self.override_config('encap_mode', mode, self.config_group)
        self._initialize_manager(vmm_domains={mocked.APIC_DOMAIN: {}})
        self.assertEqual(1, len(self.mgr.domains))
        dom = self.mgr.domains[0]
        self._mock_db_calls(self.mgr)

        dom._ensure_mcast_ns_created_on_apic = mock.Mock()
        self.mgr.ensure_infra_created_on_apic()

        if mode != 'vxlan':
            dom._ensure_mcast_ns_created_on_apic.assert_not_called()
        else:
            self.assertTrue(dom._ensure_mcast_ns_created_on_apic.called)

    def test_encap_mode_default(self):
        self._test_encap_mode(None)

    def test_encap_mode_vlan(self):
        self._test_encap_mode('vlan')

    def test_encap_mode_vxlan(self):
        self._test_encap_mode('vxlan')

    def test_vpc_dict(self):
        self.override_config('apic_vpc_pairs', ['3:4', '20:30'],
                             self.config_group)
        self._initialize_manager(set_network_config=False)
        self.assertEqual({'3': '4', '4': '3', '20': '30', '30': '20'},
                         self.mgr.vpc_dict)


class TestCiscoApicManagerNewConf(TestCiscoApicManager):

    def setUp(self):
        # Switch to new-style APIC config
        super(TestCiscoApicManagerNewConf, self).setUp(config_group='apic')

    def test_ensure_epg_created(self):
        pass

    def test_ensure_epg_created_exc(self):
        pass

    def test_vmm_creation(self):
        self.override_config('apic_vmm_type', 'OpenStack', 'apic')
        self._initialize_manager(vmm_domains={mocked.APIC_DOMAIN + '1': {},
                                              mocked.APIC_DOMAIN + '2': {}})
        self.assertEqual(2, len(self.mgr.domains))
        self.mgr.domains[0]._ensure_vmm_domain_created_on_apic = mock.Mock()
        self.mgr.domains[1]._ensure_vmm_domain_created_on_apic = mock.Mock()
        self._mock_db_calls(self.mgr)

        self.mgr.ensure_infra_created_on_apic()
        (self.mgr.domains[0]._ensure_vmm_domain_created_on_apic.
            assert_called_once_with(apic_domain.APIC_VMM_TYPE_OPENSTACK,
                                    self.mgr.domains[0].name,
                                   mock.ANY, mock.ANY, mock.ANY,
                                   vlan_ns_dn=mock.ANY))
        (self.mgr.domains[1]._ensure_vmm_domain_created_on_apic.
            assert_called_once_with(apic_domain.APIC_VMM_TYPE_OPENSTACK,
                                    self.mgr.domains[1].name,
                                    mock.ANY, mock.ANY, mock.ANY,
                                    vlan_ns_dn=mock.ANY))
        self.assertEqual(
            set([mocked.APIC_DOMAIN + '1', mocked.APIC_DOMAIN + '2']),
            set([self.mgr.domains[0].name, self.mgr.domains[1].name]))

    def test_vmware_vmm_creation(self):
        pass
