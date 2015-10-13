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

import argparse
import logging as log

from apicapi import apic_client

POD_POLICY_GROUP_DN_PATH = 'uni/fabric/funcprof/podpgrp-%s'


def ensure_bgp_pod_policy_created_on_apic(args):
    apic = apic_client.RestClient(log, "", [args.apic_ip],
                                  args.apic_username,
                                  args.apic_password, args.ssl,
                                  verify=args.insecure)
    bgp_pol_name = 'default'
    asn = args.asn
    pp_group_name = 'default'
    p_selector_name = 'default'
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
            p_selector_name, tDn=POD_POLICY_GROUP_DN_PATH % pp_group_name,
            transaction=trs)


parser = argparse.ArgumentParser(description='Cleans APIC infra profiles')
parser.add_argument('apic_ip', help='APIC ip address')
parser.add_argument('apic_username', help='APIC username')
parser.add_argument('apic_password', help='APIC password')
parser.add_argument('--ssl', help='Whether to use SSL or not', default=False)
parser.add_argument('--insecure', help='Verify server certificate',
                    action='store_false')
parser.add_argument('--asn', help='AS number for bgp policy', default='1')


def main():
    args = parser.parse_args()
    ensure_bgp_pod_policy_created_on_apic(args)
