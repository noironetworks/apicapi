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

from apicapi.tools.cli import common


@click.group()
def apicapi():
    pass

@apicapi.command(name='neutron-sync')
@common.neutron_options
def neutron_sync(*args, **kwargs):
    click.echo('%s' % kwargs['os_username'])


@apicapi.command(name='bgp-pod-policy-create')
@click.option('--asn', help='Autonomous system number', default='1')
@common.apic_options
@common.pass_apic_client
def bgp_pod_policy_create(apic, asn, **kwargs):
    bgp_pol_name = 'default'
    asn = asn
    pp_group_name = 'default'
    p_selector_name = 'default'
    pod_policy_group_dn_path = 'uni/fabric/funcprof/podpgrp-%s'

    with apic.transaction() as trs:
        apic.bgpInstPol.create(bgp_pol_name, transaction=trs)
        if not apic.bgpRRP.get_subtree(bgp_pol_name):
            for node in [x for x in apic.fabricNode.list_all()
                         if x['role'] == 'spine']:
                apic.bgpRRNodePEp.create(bgp_pol_name, node['id'],
                                         transaction=trs)

        apic.bgpAsP.create(bgp_pol_name, asn=asn, transaction=trs)

        apic.fabricPodPGrp.create(pp_group_name, transaction=trs)
        reference = apic.fabricRsPodPGrpBGPRRP.get(pp_group_name)
        if not reference or not reference['tnBgpInstPolName']:
            apic.fabricRsPodPGrpBGPRRP.update(
                pp_group_name,
                tnBgpInstPolName=apic.bgpInstPol.name(bgp_pol_name),
                transaction=trs)

        apic.fabricPodS__ALL.create(p_selector_name, type='ALL',
                                    transaction=trs)
        apic.fabricRsPodPGrp.create(
            p_selector_name, tDn=pod_policy_group_dn_path % pp_group_name,
            transaction=trs)


if __name__ == '__main__':
    apicapi(auto_envvar_prefix='APICAPI')
