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
# @author: Mandeep Dhami (dhami@noironetworks.com), Cisco Systems Inc.

import re

import contextlib

LOG = None


NAMING_STRATEGY_UUID = 'use_uuid'
NAMING_STRATEGY_NAMES = 'use_name'
NAME_TYPE_TENANT = 'tenant'
NAME_TYPE_NETWORK = 'network'
NAME_TYPE_SUBNET = 'subnet'
NAME_TYPE_PORT = 'port'
NAME_TYPE_ROUTER = 'router'
NAME_TYPE_APP_PROFILE = 'app-profile'


@contextlib.contextmanager
def mapper_context(context):
    if context and (not hasattr(context, '_plugin_context') or
                    context._plugin_context is None):
        context._plugin_context = context  # temporary circular reference
        yield context
        context._plugin_context = None     # break circular reference
    else:
        yield context


class APICNameMapper(object):
    def __init__(self, db, log, keyclient, keystone_authtoken,
                 strategy=NAMING_STRATEGY_UUID):
        self.db = db
        self.strategy = strategy
        self.keystone = None
        self.keyclient = keyclient
        self.keystone_authtoken = keystone_authtoken
        self.tenants = {}
        global LOG
        LOG = log.getLogger(__name__)

    def mapper(name_type):
        """Wrapper to land all the common operations between mappers."""
        def wrap(func):
            def inner(inst, context, resource_id, remap=False):
                if remap:
                    inst.db.delete_apic_name(resource_id)
                else:
                    saved_name = inst.db.get_apic_name(resource_id,
                                                       name_type)
                    if saved_name:
                        return ApicName(saved_name[0], resource_id, context,
                                        inst, func.__name__)
                try:
                    name = func(inst, context, resource_id)
                except Exception:
                    LOG.exception(("Exception in looking up name %s"),
                                  name_type)
                    raise

                result = resource_id
                if name:
                    if inst.strategy == NAMING_STRATEGY_NAMES:
                        result = name
                    elif inst.strategy == NAMING_STRATEGY_UUID:
                        result = name + "-" + result
                result = re.sub(r"-+", "-", result)
                inst.db.update_apic_name(resource_id, name_type, result)
                return ApicName(result, resource_id, context, inst,
                                func.__name__)
            return inner
        return wrap

    @mapper(NAME_TYPE_TENANT)
    def tenant(self, context, tenant_id):
        tenant_name = None
        if tenant_id in self.tenants:
            tenant_name = self.tenants.get(tenant_id)
        else:
            if self.keystone is None:
                keystone_conf = self.keystone_authtoken
                auth_url = ('%s://%s:%s/v2.0/' % (
                    keystone_conf.auth_protocol,
                    keystone_conf.auth_host,
                    keystone_conf.auth_port))
                username = keystone_conf.admin_user
                password = keystone_conf.admin_password
                project_name = keystone_conf.admin_tenant_name
                self.keystone = self.keyclient.Client(
                    auth_url=auth_url,
                    username=username,
                    password=password,
                    tenant_name=project_name)
            for tenant in self.keystone.tenants.list():
                self.tenants[tenant.id] = tenant.name
                if tenant.id == tenant_id:
                    tenant_name = tenant.name
        return tenant_name

    @mapper(NAME_TYPE_NETWORK)
    def network(self, context, network_id):
        network = context._plugin.get_network(
            context._plugin_context, network_id)
        network_name = network['name']
        return network_name

    @mapper(NAME_TYPE_SUBNET)
    def subnet(self, context, subnet_id):
        subnet = context._plugin.get_subnet(context._plugin_context, subnet_id)
        subnet_name = subnet['name']
        return subnet_name

    @mapper(NAME_TYPE_PORT)
    def port(self, context, port_id):
        port = context._plugin.get_port(context._plugin_context, port_id)
        port_name = port['name']
        return port_name

    @mapper(NAME_TYPE_ROUTER)
    def router(self, context, router_id):
        return context._plugin_context.session.execute(
            'SELECT * from routers WHERE id = :id',
            {'id': router_id}).fetchone().name

    def app_profile(self, context, app_profile, remap=False):
        if remap:
            self.db.delete_apic_name('app_profile')
        # Check if a profile is already been used
        saved_name = self.db.get_apic_name('app_profile',
                                           NAME_TYPE_APP_PROFILE)
        if not saved_name:
            self.db.update_apic_name('app_profile', NAME_TYPE_APP_PROFILE,
                                     app_profile)
            result = app_profile
        else:
            result = saved_name[0]
        return ApicName(result, app_profile, None,
                        self, self.app_profile.__name__)


class ApicName(object):

    def __init__(self, mapped, uid='', context=None, inst=None, fname=''):
        self.uid = uid
        self.context = context
        self.inst = inst
        self.fname = fname
        self.value = mapped

    def renew(self):
        if self.uid and self.inst and self.fname:
            # temporary circular reference
            with mapper_context(self.context) as ctx:
                result = getattr(self.inst, self.fname)(ctx, self.uid,
                                                        remap=True)
            self.value = result.value
            return self

    def __str__(self):
        return self.value
