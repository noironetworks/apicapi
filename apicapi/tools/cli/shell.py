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
import os
import subprocess
import time

from apicapi.tools.cli import common
from apicapi.tools import host_report
from neutronclient.common import exceptions as n_exc
from aim.api import resource as aim_resource
from aim.api import infra as aim_infra_resource
from aim import aim_manager
from aim import context as aim_context
from aim import utils as aim_utils
from aim.db import api
from aim import config


@click.group()
def apicapi():
    """Commands for APIC plugin"""
    pass


@apicapi.command(name='neutron-sync')
@common.os_options
@common.pass_neutron_client
def neutron_sync(neutron, *args, **kwargs):
    message = ('The name used for this network is reserved for on '
               'demand synchronization.')
    try:
        neutron.create_network({'network': {'name': 'apic-sync-network'}})
    except Exception as e:
        if message in str(e):
            click.echo("Synchronization complete.")
        elif (isinstance(e, n_exc.NeutronClientException) and
              e.status_code == 504):
            click.echo("Request timed out before the synchronization could "
                       "complete. Please use --http-timeout parameter to "
                       "specify a bigger time-out value in seconds.")
        else:
            raise


@apicapi.command(name='route-reflector-create')
@click.option('--asn', help='Autonomous system number', default='1')
@common.apic_options
@common.pass_apic_client
def apic_route_reflector_create(apic, asn, **kwargs):
    """APIC command for route reflector.

    Creates a default route reflector on the APIC backend if needed.
    """
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


@apicapi.command(name='host-report')
def host_report_cmd(*args, **kwargs):
    """Generate a host report for tech support"""
    host_report.main()


@apicapi.command(name='erspan-create')
@click.option('--neutron_port', help='Neutron port UUID')
@click.option('--dest_ip', help='remote destination ip address')
@click.option('--flow_id', help='Flow Id', default='1')
def erspan_cmd(neutron_port, dest_ip, flow_id, *args, **kwargs):
    global_opts = [
    config.cfg.StrOpt('apic_system_id',
                      help="Prefix for APIC domain/names/profiles created"),
    ]
    config.CONF.register_opts(global_opts)

    args = ['--config-file','/etc/aim/aim.conf' , '--config-file', '/etc/aim/aimctl.conf']
    config.CONF(project='aim', args=args)

    ctx = aim_context.AimContext(store=api.get_store(expire_on_commit=True))
    aimManager = aim_manager.AimManager()
    mac_addr = subprocess.check_output("openstack port show %s -c mac_address -f value" % neutron_port, shell=True)
    mac = mac_addr.upper()
    epg_net_id = subprocess.check_output("openstack port show %s -c network_id -f value" % neutron_port, shell=True)
    tenant_prj_id = subprocess.check_output("openstack port show %s -c project_id -f value" % neutron_port, shell=True)
    name_id = subprocess.check_output("openstack port show %s -c id -f value" % neutron_port, shell=True)
    grp_name=name_id.decode('utf-8').rstrip("\n")
    fvCEp_dn = 'uni/tn-prj_' + tenant_prj_id.decode('utf-8').rstrip("\n") + '/ap-OpenStack/epg-net_' + epg_net_id.decode('utf-8').rstrip("\n") + '/cep-' + mac.decode('utf-8').rstrip("\n")

    vsrc_grp_aim = aim_resource.SpanVsourceGroup(name=grp_name)
    aimManager.create(ctx, vsrc_grp_aim)
    print(vsrc_grp_aim)

    vsrc = aim_resource.SpanVsource(vsg_name=grp_name, name=grp_name)
    aimManager.create(ctx, vsrc)
    aimManager.update(ctx, vsrc, src_paths=[fvCEp_dn])

    vdest_grp_aim = aim_resource.SpanVdestGroup(name=grp_name)
    aimManager.create(ctx, vdest_grp_aim)
    vdest = aim_resource.SpanVdest(vdg_name=grp_name, name=grp_name)
    aimManager.create(ctx, vdest)
    vepgSum = aim_resource.SpanVepgSummary(vdg_name=grp_name, vd_name=grp_name)
    aimManager.create(ctx, vepgSum)
    aimManager.update(ctx, vepgSum, dst_ip=dest_ip, flow_id=flow_id)

    check_topology = aimManager.find(ctx, aim_resource.Topology)
    if not check_topology:
        topology_aim = aim_resource.Topology()
        aimManager.create(ctx, topology_aim)
        time.sleep(5)
    bundle_path = aimManager.find(ctx, aim_infra_resource.OpflexDevice)
    fabricpaths=[]
    for bundle in bundle_path:
        fabricpaths.append(bundle.fabric_path_dn)

    grpNames=[]
    for grpname in fabricpaths:
        lhs, rhs = grpname.split('/pathep-[')
        grpNames.append(rhs.rstrip("]"))
    acc_bundle_names = list(set(grpNames))

    for acc_name in acc_bundle_names:
        time.sleep(2)
        acc_bndle_grp_aim = aim_resource.InfraAccBundleGroup(name=acc_name)
        aimManager.update(ctx, acc_bndle_grp_aim, span_vsource_group_names=[grp_name],
            span_vdest_group_names=[grp_name])

    span_lbl = aim_resource.SpanSpanlbl(vsg_name=grp_name, name=grp_name)
    aimManager.create(ctx, span_lbl)
    aimManager.update(ctx, span_lbl, tag='yellow-green')


@apicapi.command(name='erspan-delete') 
@click.option('--neutron_port', help='Neutron port uuid')
def erspan_cmd_del(neutron_port, *args, **kwargs):
    global_opts = [
    config.cfg.StrOpt('apic_system_id',
                      help="Prefix for APIC domain/names/profiles created"),
    ]
    config.CONF.register_opts(global_opts)
    args = ['--config-file','/etc/aim/aim.conf' , '--config-file', '/etc/aim/aimctl.conf']
    config.CONF(project='aim', args=args)
    
    ctx = aim_context.AimContext(store=api.get_store(expire_on_commit=True))
    aimManager = aim_manager.AimManager()
    name_id = subprocess.check_output("openstack port show %s -c id -f value" % neutron_port, shell=True)
    grp_name=name_id.decode('utf-8').rstrip("\n")
    
    bundle_path = aimManager.find(ctx, aim_infra_resource.OpflexDevice)
    fabricpaths=[]
    for bundle in bundle_path:
        fabricpaths.append(bundle.fabric_path_dn)

    grpNames=[]
    for grpname in fabricpaths:
        lhs, rhs = grpname.split('/pathep-[')
        grpNames.append(rhs.rstrip("]"))
    acc_bundle_names = list(set(grpNames))
    
    for acc_name in acc_bundle_names:
        acc_bndle_grp_aim = aim_resource.InfraAccBundleGroup(name=acc_name)
        aimManager.update(ctx, acc_bndle_grp_aim, span_vsource_group_names=[],
            span_vdest_group_names=[])
                
    span_lbl = aim_resource.SpanSpanlbl(vsg_name=grp_name, name=grp_name)
    aimManager.delete(ctx, span_lbl)
    
    vsrc = aim_resource.SpanVsource(vsg_name=grp_name, name=grp_name)
    aimManager.delete(ctx, vsrc)
    vsrc_grp_aim = aim_resource.SpanVsourceGroup(name=grp_name)
    aimManager.delete(ctx, vsrc_grp_aim)
    print("deleted sourceGrp")
    
    vepgSum = aim_resource.SpanVepgSummary(vdg_name=grp_name, vd_name=grp_name)
    aimManager.delete(ctx, vepgSum)
    vdest = aim_resource.SpanVdest(vdg_name=grp_name, name=grp_name)
    aimManager.delete(ctx, vdest)
    vdest_grp_aim = aim_resource.SpanVdestGroup(name=grp_name)
    vdest_grp_aim = aim_resource.SpanVdestGroup(name=grp_name)
    aimManager.delete(ctx, vdest_grp_aim)
    print("deleted destination")

def run():
    apicapi(auto_envvar_prefix='APICAPI')


if __name__ == '__main__':
    run()
