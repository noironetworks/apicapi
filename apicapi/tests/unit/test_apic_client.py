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

import mock
import requests
import requests.exceptions

from apicapi import apic_client as apic
from apicapi import apic_mapper as mapper
from apicapi import exceptions as cexc
from apicapi.tests import base
from apicapi.tests.unit.common import test_apic_common as mocked


class TestCiscoApicClient(base.BaseTestCase, mocked.ControllerMixin):

    def setUp(self):
        super(TestCiscoApicClient, self).setUp()
        self.set_up_mocks()
        self.apic = apic.RestClient(self.log, mocked.APIC_SYSTEM_ID,
                                    mocked.APIC_HOSTS)
        self.transaction = apic.Transaction(self.apic)
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(self.clean_up_pvt_key_file)

    def _mock_authenticate(self, timeout=None):
        if timeout is None:
            timeout = 300
        self.reset_reponses()
        self.mock_apic_manager_login_responses(timeout=timeout)
        self.apic.login(mocked.APIC_USR, mocked.APIC_PWD)

    def _mock_authenticate_certificate(self):
        self.reset_reponses()
        self.enable_signature_check()
        pk = self.create_pvt_key_file()
        self.mock_response_for_certificate_fetch(mocked.APIC_USR_CERT_NAME)
        self.apic.set_private_key(mocked.APIC_USR, mocked.APIC_USR_CERT_NAME,
                                  pk)

    def test_login_by_instantiation(self):
        self.reset_reponses()
        self.mock_apic_manager_login_responses()
        apic2 = apic.RestClient(self.log,
                                mocked.APIC_SYSTEM_ID,
                                mocked.APIC_HOSTS,
                                usr=mocked.APIC_USR, pwd=mocked.APIC_PWD)
        self.assertIsNotNone(apic2.authentication)
        self.assertEqual(apic2.username, mocked.APIC_USR)

    def test_client_session_login_ok(self):
        self._mock_authenticate()
        self.assertEqual(
            self.apic.authentication['userName'], mocked.APIC_USR)
        self.assertTrue(self.apic.api_base[0].startswith('https://'))
        self.assertEqual(self.apic.username, mocked.APIC_USR)
        self.assertIsNotNone(self.apic.authentication)
        self.apic = apic.RestClient(self.log,
                                    mocked.APIC_SYSTEM_ID,
                                    mocked.APIC_HOSTS, mocked.APIC_PORT,
                                    ssl=False)
        self.assertTrue(self.apic.api_base[0].startswith('http://'))

    def test_client_session_login_fail(self):
        self.mock_error_post_response(requests.codes.unauthorized,
                                      code='599',
                                      text=u'Fake error')
        self.assertRaises(cexc.ApicResponseNotOk, self.apic.login,
                          mocked.APIC_USR, mocked.APIC_PWD)

    def test_client_session_login_timeout(self):
        self.response['post'].append(requests.exceptions.Timeout)
        self.response['post'].append(requests.exceptions.Timeout)
        self.assertRaises(cexc.ApicHostNoResponse, self.apic.login,
                          mocked.APIC_USR, mocked.APIC_PWD)

    def test_client_session_logout_ok(self):
        self.mock_response_for_post('aaaLogout')
        self.apic.logout()
        self.assertIsNone(self.apic.authentication)
        # Multiple signouts should not cause an error
        self.apic.logout()
        self.assertIsNone(self.apic.authentication)

    def test_client_session_logout_fail(self):
        self._mock_authenticate()
        self.mock_error_post_response(requests.codes.timeout,
                                      code='123', text='failed')
        self.assertRaises(cexc.ApicResponseNotOk, self.apic.logout)

    def test_client_certificate_login(self):
        self.reset_reponses()
        self.enable_signature_check()
        pk = self.create_pvt_key_file()
        self.mock_response_for_certificate_fetch(mocked.APIC_USR)
        apic.RestClient(self.log, mocked.APIC_SYSTEM_ID,
                        mocked.APIC_HOSTS,
                        usr=mocked.APIC_USR,
                        cert_name=mocked.APIC_USR_CERT_NAME,
                        private_key_file=pk)

    def test_query_not_logged_in(self):
        self.apic.authentication = None
        self.assertRaises(cexc.ApicSessionNotLoggedIn,
                          self.apic.fvTenant.get, mocked.APIC_TENANT)

    def test_query_no_response(self):
        self._mock_authenticate()
        requests.Session.get = mock.Mock(return_value=None)
        self.assertRaises(cexc.ApicHostNoResponse,
                          self.apic.fvTenant.get, mocked.APIC_TENANT)

    def test_query_error_response_no_data(self):
        self._mock_authenticate()
        self.mock_error_get_response(requests.codes.bad)  # No error attrs.
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.apic.fvTenant.get, mocked.APIC_TENANT)

    def test_generic_get_data(self):
        self._mock_authenticate()
        self._do_generic_get_data()

    def test_generic_get_data_certificate(self):
        self._mock_authenticate_certificate()
        self._do_generic_get_data()

    def _do_generic_get_data(self):
        self.mock_response_for_get('topSystem', name='ifc1')
        top_system = self.apic.get_data('class/topSystem')
        self.assertIsNotNone(top_system)
        name = top_system[0]['topSystem']['attributes']['name']
        self.assertEqual(name, 'ifc1')

    def test_session_timeout_refresh_ok(self):
        self._mock_authenticate(timeout=-1)
        # Client will do refresh before getting tenant
        self.mock_response_for_get('aaaLogin', token='ok',
                                   refreshTimeoutSeconds=300)
        self.mock_response_for_get('fvTenant', name=mocked.APIC_TENANT)
        tenant = self.apic.fvTenant.get(mocked.APIC_TENANT)
        self.assertEqual(tenant['name'], mocked.APIC_TENANT)

    def test_session_timeout_refresh_no_cookie(self):
        self._mock_authenticate(timeout=-1)
        # Client will do refresh before getting tenant
        self.mock_response_for_get('aaaLogin', notoken='test')
        self.assertRaises(cexc.ApicResponseNoCookie,
                          self.apic.fvTenant.get, mocked.APIC_TENANT)

    def test_session_timeout_refresh_error(self):
        self._mock_authenticate(timeout=-1)
        self.mock_error_get_response(requests.codes.timeout,
                                     code='503', text=u'timed out')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.apic.fvTenant.get, mocked.APIC_TENANT)

    def test_session_timeout_refresh_timeout_error(self):
        self._mock_authenticate(timeout=-1)
        # Client will try to get refresh, we fake a refresh error.
        self.mock_error_get_response(requests.codes.bad_request,
                                     code='403',
                                     text=u'Token was invalid. Expired.')
        # Client will then try to re-login.
        self.mock_apic_manager_login_responses()
        # Finally the client will try to get the tenant.
        self.mock_response_for_get('fvTenant', name=mocked.APIC_TENANT)
        tenant = self.apic.fvTenant.get(mocked.APIC_TENANT)
        self.assertEqual(tenant['name'], mocked.APIC_TENANT)

    def test_lookup_mo_bad_token_retry(self):
        self._mock_authenticate()
        # For the first get request we mock a bad token.
        self.mock_error_get_response(requests.codes.bad_request,
                                     code='403',
                                     text=u'Token was invalid. Expired.')
        # Client will then try to re-login.
        self.mock_apic_manager_login_responses()
        # Then the client will retry to get the tenant.
        self.mock_response_for_get('fvTenant', name=mocked.APIC_TENANT)
        tenant = self.apic.fvTenant.get(mocked.APIC_TENANT)
        self.assertEqual(tenant['name'], mocked.APIC_TENANT)

    def test_lookup_nonexistant_mo(self):
        self._mock_authenticate()
        self.mock_response_for_get('fvTenant')
        self.assertIsNone(self.apic.fvTenant.get(mocked.APIC_TENANT))

    def test_lookup_existing_mo(self):
        self._mock_authenticate()
        self.mock_response_for_get('fvTenant', name='infra')
        tenant = self.apic.fvTenant.get('infra')
        self.assertEqual(tenant['name'], 'infra')

    def test_list_mos_ok(self):
        self._mock_authenticate()
        self.mock_response_for_get('fvTenant', name='t1')
        self.mock_append_to_response('fvTenant', name='t2')
        tlist = self.apic.fvTenant.list_all()
        self.assertIsNotNone(tlist)
        self.assertEqual(len(tlist), 2)

    def test_list_mo_names_ok(self):
        self._mock_authenticate()
        self.mock_response_for_get('fvTenant', name='t1')
        self.mock_append_to_response('fvTenant', name='t2')
        tnlist = self.apic.fvTenant.list_names()
        self.assertIsNotNone(tnlist)
        self.assertEqual(len(tnlist), 2)
        self.assertIn('t1', tnlist)
        self.assertIn('t2', tnlist)

    def test_list_mos_split_class_fail(self):
        self._mock_authenticate()
        self.mock_response_for_get('fvnsEncapBlk', name='Blk1')
        encap_blks = self.apic.fvnsEncapBlk__vlan.list_all()
        self.assertEqual(len(encap_blks), 1)

    def test_delete_mo_ok(self):
        self._mock_authenticate()
        self.mock_response_for_post('fvTenant')
        self.assertTrue(self.apic.fvTenant.delete(mocked.APIC_TENANT))

    def test_create_mo_ok(self):
        self._mock_authenticate()
        self._do_create_mo_ok()

    def test_create_mo_ok_certificate(self):
        self._mock_authenticate_certificate()
        self._do_create_mo_ok()

    def _do_create_mo_ok(self):
        self.mock_response_for_post('fvTenant', name=mocked.APIC_TENANT)
        self.mock_response_for_get('fvTenant', name=mocked.APIC_TENANT)
        self.apic.fvTenant.create(mocked.APIC_TENANT)
        tenant = self.apic.fvTenant.get(mocked.APIC_TENANT)
        self.assertEqual(tenant['name'], mocked.APIC_TENANT)

    def test_create_mo_already_exists(self):
        self._mock_authenticate()
        self.mock_error_post_response(requests.codes.bad_request,
                                      code='103',
                                      text=u'Fake 103 error')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.apic.physDomP.create, mocked.APIC_DOMAIN)

    def test_create_mo_with_prereq(self):
        self._mock_authenticate()
        self.mock_response_for_post('fvTenant', name=mocked.APIC_TENANT)
        self.mock_response_for_post('fvBD', name=mocked.APIC_NETWORK)
        self.mock_response_for_get('fvBD', name=mocked.APIC_NETWORK)
        bd_args = mocked.APIC_TENANT, mocked.APIC_NETWORK
        self.apic.fvBD.create(*bd_args)
        network = self.apic.fvBD.get(*bd_args)
        self.assertEqual(network['name'], mocked.APIC_NETWORK)

    def test_create_mo_prereq_exists(self):
        self._mock_authenticate()
        self.mock_response_for_post('physDomP', name=mocked.APIC_DOMAIN)
        self.mock_response_for_get('physDomP', name=mocked.APIC_DOMAIN)
        self.apic.physDomP.create(mocked.APIC_DOMAIN)
        dom = self.apic.physDomP.get(mocked.APIC_DOMAIN)
        self.assertEqual(dom['name'], mocked.APIC_DOMAIN)

    def test_create_mo_fails(self):
        self._mock_authenticate()
        self.mock_error_post_response(requests.codes.bad_request,
                                      code='not103',
                                      text=u'Fake not103 error')
        bd_args = mocked.APIC_TENANT, mocked.APIC_NETWORK
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.apic.fvBD.create, *bd_args)

    def test_update_mo(self):
        self._mock_authenticate()
        self.mock_response_for_post('fvTenant', name=mocked.APIC_TENANT)
        self.mock_response_for_get('fvTenant', name=mocked.APIC_TENANT,
                                   more='extra')
        self.apic.fvTenant.update(mocked.APIC_TENANT, more='extra')
        tenant = self.apic.fvTenant.get(mocked.APIC_TENANT)
        self.assertEqual(tenant['name'], mocked.APIC_TENANT)
        self.assertEqual(tenant['more'], 'extra')

    def test_attr_fail_empty_list(self):
        self._mock_authenticate()
        self.mock_response_for_get('fvTenant')  # No attrs for tenant.
        self.assertIsNone(self.apic.fvTenant.get(mocked.APIC_TENANT))

    def test_attr_fail_other_obj(self):
        self._mock_authenticate()
        self.mock_response_for_get('other', name=mocked.APIC_TENANT)
        self.assertIsNone(self.apic.fvTenant.get(mocked.APIC_TENANT))

    def test_create_multiple_root_fail(self):
        self.apic.fvSubnet.create('root1', 'bd', 'subnet',
                                  transaction=self.transaction)
        self.assertRaises(cexc.ApicInvalidTransactionMultipleRoot,
                          self.apic.fvSubnet.create,
                          'root2', 'bd', 'subnet',
                          transaction=self.transaction)

    def test_sub_transaction(self):
        with self.apic.transaction() as trs:
            trs.commit = mock.Mock()
            self.apic.fvSubnet.create(mocked.APIC_TENANT, 'bd', 'subnet',
                                      transaction=trs)
            self.assertFalse(trs.commit.called)
            self.apic.fvSubnet.create(mocked.APIC_TENANT, 'bd1', 'subnet',
                                      transaction=trs)
            self.assertFalse(trs.commit.called)
            self.apic.fvSubnet.create(mocked.APIC_TENANT, 'bd1', 'subnet1',
                                      transaction=trs)
            self.assertFalse(trs.commit.called)
        self.assertEqual(1, trs.commit.call_count)

    def test_sub_transaction_top_send(self):

        trs = apic.Transaction(self.apic, top_send=True)
        trs.post_body = mock.Mock()
        # first root
        self.apic.fvSubnet.create(mocked.APIC_TENANT, 'bd', 'subnet',
                                  transaction=trs)
        # Second root with children
        self.apic.fvBD.create(mocked.APIC_TENANT, 'bd1', transaction=trs)
        self.apic.fvSubnet.create(mocked.APIC_TENANT, 'bd1', 'subnet',
                                  transaction=trs)
        self.apic.fvSubnet.create(mocked.APIC_TENANT, 'bd1', 'subnet1',
                                  transaction=trs)
        # Third root
        self.apic.vzSubj.create(mocked.APIC_TENANT, 'c', 's',
                                transaction=trs)
        self.apic.vzRsFiltAtt__In.create(mocked.APIC_TENANT, 'c', 's', 'i1',
                                         transaction=trs)
        roots = trs.get_top_level_roots()
        # Roots are BD1 and bd/subnet
        self.assertEqual(3, len(roots))
        # Verify children are there
        for item in roots:
            if item[1].mo_rn == 'BD-bd':
                self.assertEqual(2, len(item[1].children))

    def test_renew_called(self):
        s_name = mapper.ApicName('name', 'id')
        s_name.renew = mock.Mock()
        self._mock_authenticate()
        self.mock_response_for_get('fvSubnet')
        self.apic.fvSubnet.create(mocked.APIC_TENANT, 'bd', s_name)
        self.assertEqual(1, s_name.renew.call_count)

    def test_renew_not_called(self):
        s_name = mapper.ApicName('name', 'id')
        s_name.renew = mock.Mock()
        self._mock_authenticate()
        self.mock_response_for_get('fvSubnet', name=s_name)
        self.apic.fvSubnet.create(mocked.APIC_TENANT, 'bd', s_name)
        self.assertFalse(s_name.renew.called)

    def test_dn_manager(self):
        manager = self.apic.dn_manager
        ctx = 'uni/tn-common/ctx-default'
        self.assertEqual(['common', 'default'], manager.decompose_context(ctx))
        ctx = 'uni/tn-common/WRONG-default'
        self.assertIsNone(manager.decompose_context(ctx))
        ctx = 'tn-common/ctx-default'
        self.assertEqual(['common', 'default'], manager.decompose_context(ctx))
        bd = 'uni/tn-common/BD-default'
        self.assertEqual(['common', 'default'],
                         manager.decompose_bridge_domain(bd))
        epg = ('uni/tn-_openstack-maple_/ap-openstack-maple_app/'
               'epg-public_ff5b842c-8a76-4cb4-8197-9f9726be44ac')
        self.assertEqual(
            ['_openstack-maple_', 'openstack-maple_app',
             'public_ff5b842c-8a76-4cb4-8197-9f9726be44ac'],
            manager.decompose_endpoint_group(epg))

    def test_aci_decompose(self):
        manager = self.apic.dn_manager
        res = manager.aci_decompose('uni/tn-ivar-wstest/BD-test/rsctx',
                                    'fvRsCtx')
        self.assertEqual(['ivar-wstest', 'test', 'rsctx'], res)

        res = manager.aci_decompose_with_type(
            'uni/tn-ivar-wstest/BD-test/rsctx', 'fvRsCtx')
        self.assertEqual([('fvTenant', 'ivar-wstest'),
                          ('fvBD', 'test'),
                          ('fvRsCtx', 'rsctx')], res)

        res = manager.aci_decompose(
            'uni/tn-ivar-wstest/BD-test/subnet-[10.10.1.1/28]', 'fvSubnet')
        self.assertEqual(['ivar-wstest', 'test', '10.10.1.1/28'], res)
        res = manager.aci_decompose_with_type(
            'uni/tn-ivar-wstest/BD-test/subnet-[10.10.1.1/28]', 'fvSubnet')
        self.assertEqual([('fvTenant', 'ivar-wstest'),
                          ('fvBD', 'test'),
                          ('fvSubnet', '10.10.1.1/28')], res)

        self.assertRaises(apic.DNManager.InvalidNameFormat,
                          manager.aci_decompose,
                          'uni/tn-ivar-wstest/BD-test', 'fvSubnet')

        self.assertRaises(apic.DNManager.InvalidNameFormat,
                          manager.aci_decompose,
                          'uni/tn-ivar-wstest/BD-test', 'fvTenant')

        res = manager.aci_decompose_with_type(
            'topology/pod-1/node-301/sys/br-[eth1/33]/odev-167776320',
            'opflexODev')
        self.assertEqual([('fabricTopology', 'topology'),
                          ('fabricPod', '1'),
                          ('fabricNode', '301'),
                          ('topSystem', 'sys'),
                          ('l2BrIf', 'eth1/33'),
                          ('opflexODev', '167776320')], res)

    def test_aci_decompose_dn_guess(self):
        manager = self.apic.dn_manager
        res = manager.aci_decompose_dn_guess(
            'uni/tn-amit1/brc-c/subj-s2/intmnl/rsfiltAtt-f', 'vzRsFiltAtt')
        self.assertEqual('vzRsFiltAtt__In', res[0])
        self.assertEqual([('fvTenant', 'amit1'),
                          ('vzBrCP', 'c'),
                          ('vzSubj', 's2'),
                          ('vzInTerm', 'intmnl'),
                          ('vzRsFiltAtt', 'f')], res[1])

        res = manager.aci_decompose_dn_guess(
            'uni/tn-amit1/brc-c/subj-s2/outtmnl/rsfiltAtt-g', 'vzRsFiltAtt')
        self.assertEqual('vzRsFiltAtt__Out', res[0])
        self.assertEqual([('fvTenant', 'amit1'),
                          ('vzBrCP', 'c'),
                          ('vzSubj', 's2'),
                          ('vzOutTerm', 'outtmnl'),
                          ('vzRsFiltAtt', 'g')], res[1])

        res = manager.aci_decompose_dn_guess(
            'uni/tn-amit1/brc-c/subj-s2/rsfiltAtt-h', 'vzRsFiltAtt')
        self.assertEqual('vzRsFiltAtt', res[0])
        self.assertEqual([('fvTenant', 'amit1'),
                          ('vzBrCP', 'c'),
                          ('vzSubj', 's2'),
                          ('vzRsFiltAtt', 'h')], res[1])

        self.assertRaises(apic.DNManager.InvalidNameFormat,
                          manager.aci_decompose_dn_guess,
                          'uni/tn-ivar-wstest/BD-test', 'vzRsFiltAtt')

        res = manager.aci_decompose_dn_guess(
            'uni/tn-tn1/BD-mybd/subnet-[10.10.10.1/28]/tag-aid', 'tagInst')
        self.assertEqual('tagInst', res[0])
        self.assertEqual([('fvTenant', 'tn1'),
                          ('fvBD', 'mybd'),
                          ('fvSubnet', '10.10.10.1/28'),
                          ('tagInst', 'aid')], res[1])

        res = manager.aci_decompose_dn_guess(
            'uni/tn-common/out-default/instP-extnet/rsprov-default',
            'fvRsProv')
        self.assertEqual('fvRsProv__Ext', res[0])
        self.assertEqual([('fvTenant', 'common'),
                          ('l3extOut', 'default'),
                          ('l3extInstP', 'extnet'),
                          ('fvRsProv', 'default')], res[1])

        old_scope = apic.ManagedObjectClass.scope
        apic.ManagedObjectClass.scope = ''
        res = manager.aci_decompose_dn_guess('uni/infra/nprof-test',
                                             'infraNodeP')
        self.assertEqual('infraNodeP', res[0])
        self.assertEqual([('infraInfra', 'infra'),
                          ('infraNodeP', 'test')], res[1])
        self.assertEqual('uni/infra/nprof-test', manager.build(res[1]))

        res = manager.aci_decompose_dn_guess(
            'uni/infra/nprof-test/leaves-201-typ-range',
            'infraLeafS')
        self.assertEqual('infraLeafS', res[0])
        self.assertEqual([('infraInfra', 'infra'),
                          ('infraNodeP', 'test'),
                          ('infraLeafS', '201,range')], res[1])
        self.assertEqual('uni/infra/nprof-test/leaves-201-typ-range',
                         manager.build(res[1]))
        self.assertEqual(
            ['infra', 'test', '201', 'range'],
            manager.aci_decompose_split(
                'uni/infra/nprof-test/leaves-201-typ-range', 'infraLeafS'))

        res = manager.aci_decompose_dn_guess(
            'uni/infra/nprof-test/rsaccPortP-[uni/infra/accportprof-test]',
            'infraRsAccPortP')
        self.assertEqual('infraRsAccPortP', res[0])
        self.assertEqual([('infraInfra', 'infra'),
                          ('infraNodeP', 'test'),
                          ('infraRsAccPortP', 'uni/infra/accportprof-test')],
                         res[1])
        self.assertEqual(
            'uni/infra/nprof-test/rsaccPortP-[uni/infra/accportprof-test]',
            manager.build(res[1]))

        res = manager.aci_decompose_dn_guess(
            'uni/infra/accportprof-test', 'infraAccPortP')
        self.assertEqual('infraAccPortP', res[0])
        self.assertEqual([('infraInfra', 'infra'),
                          ('infraAccPortP', 'test')],
                         res[1])
        self.assertEqual(
            'uni/infra/accportprof-test', manager.build(res[1]))

        res = manager.aci_decompose_dn_guess(
            'uni/infra/accportprof-test/hports-test-typ-test', 'infraHPortS')
        self.assertEqual('infraHPortS', res[0])
        self.assertEqual([('infraInfra', 'infra'),
                          ('infraAccPortP', 'test'),
                          ('infraHPortS', 'test,test')],
                         res[1])
        self.assertEqual(
            'uni/infra/accportprof-test/hports-test-typ-test',
            manager.build(res[1]))

        apic.ManagedObjectClass.scope = old_scope

    def test_aci_decompose_fault_dn(self):
        manager = self.apic.dn_manager
        res = manager.aci_decompose('uni/tn-amit1/brc-c/fault-F1228',
                                    'faultInst')
        self.assertEqual(['amit1', 'c', 'F1228'], res)

        res = manager.aci_decompose(
            'uni/tn-amit1/brc-c/subj-s2/intmnl/rsfiltAtt-f/fault-F1111',
            'faultInst')
        self.assertEqual(['amit1', 'c', 's2', 'intmnl', 'f', 'F1111'], res)

        res = manager.aci_decompose(
            'uni/tn-amit1/brc-c/subj-s2/outtmnl/rsfiltAtt-g/fault-F1111',
            'faultInst')
        self.assertEqual(['amit1', 'c', 's2', 'outtmnl', 'g', 'F1111'], res)

        res = manager.aci_decompose(
            'uni/tn-amit1/brc-c/subj-s2/rsfiltAtt-h/fault-F1111',
            'faultInst')
        self.assertEqual(['amit1', 'c', 's2', 'h', 'F1111'], res)

    def test_prefix_mos(self):
        prefix_mos = apic.ManagedObjectClass.prefix_to_mos
        self.assertEqual('fvBD', prefix_mos['BD'])
        self.assertEqual('fvRsCtx', prefix_mos['rsctx'])
        self.assertEqual('vzRsFiltAtt', prefix_mos['rsfiltAtt'])
        self.assertEqual('infraRsAttEntP', prefix_mos['rsattEntP'])

    def test_build_dn(self):
        clnt = apic.RestClient(self.log, mocked.APIC_SYSTEM_ID,
                               mocked.APIC_HOSTS, scope_names=False)
        manager = clnt.dn_manager
        self.assertEqual('uni/tn-amit1/brc-c/subj-s2/rsfiltAtt-h',
                         manager.build([('fvTenant', 'amit1'),
                                        ('vzBrCP', 'c'),
                                        ('vzSubj', 's2'),
                                        ('vzRsFiltAtt', 'h')]))

        self.assertEqual('uni/tn-amit1/brc-c/subj-s2/intmnl/rsfiltAtt-f',
                         manager.build([('fvTenant', 'amit1'),
                                        ('vzBrCP', 'c'),
                                        ('vzSubj', 's2'),
                                        ('vzInTerm', 'intmnl'),
                                        ('vzRsFiltAtt', 'f')]))
        self.assertEqual(
            'topology/pod-1/node-301/sys/br-[eth1/33]/odev-167776320',
            manager.build([('fabricTopology', 'topology'),
                          ('fabricPod', '1'),
                          ('fabricNode', '301'),
                          ('topSystem', 'sys'),
                          ('l2BrIf', 'eth1/33'),
                          ('opflexODev', '167776320')]))

    def test_aci_decompose_dn_nested_parens(self):
        manager = self.apic.dn_manager
        res = manager.aci_decompose(
            'uni/tn-tenant1/ap-lab/epg-web/rspathAtt-'
            '[topology/pod-1/paths-101/pathep-[eth1/2]]',
            'fvRsPathAtt')
        self.assertEqual(['tenant1', 'lab', 'web',
                          'topology/pod-1/paths-101/pathep-[eth1/2]'],
                         res)

    def test_filter_rns(self):
        manager = self.apic.dn_manager
        res = manager.filter_rns([('fvTenant', 'amit1'),
                                  ('vzBrCP', 'c'),
                                  ('vzSubj', 's2'),
                                  ('vzInTerm', 'intmnl'),
                                  ('vzRsFiltAtt', 'f')])
        self.assertEqual(['amit1', 'c', 's2', 'f'], res)

        res = manager.filter_rns([('fvTenant', 'amit1'),
                                  ('vnsSvcCont', 'svcCont'),
                                  ('vnsSvcRedirectPol', 'r1')])
        self.assertEqual(['amit1', 'r1'], res)

        res = manager.filter_rns([('fvTenant', 't1'),
                                  ('vnsLDevCtx', 'contract1,graph1,N1')])
        self.assertEqual(['t1', 'contract1', 'graph1', 'N1'], res)

    def test_rn_base(self):
        manager = self.apic.dn_manager
        self.assertEqual('uni', manager.get_rn_base('tn-test'))
        self.assertEqual('topology', manager.get_rn_base('pod-test'))
