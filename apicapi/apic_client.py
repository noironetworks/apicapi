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

import collections
import contextlib
import json
import re
import time

import requests
import requests.exceptions as rexc

from apicapi import exceptions as cexc


LOG = None

APIC_CODE_FORBIDDEN = str(requests.codes.forbidden)
APIC_CODE_SSL_ERROR = str(requests.codes.gateway_timeout)

FALLBACK_EXCEPTIONS = (rexc.ConnectionError, rexc.Timeout,
                       rexc.TooManyRedirects, rexc.InvalidURL)
SLEEP_TIME = 0.03
SLEEP_ON_FULL_QUEUE = 1

REFRESH_CODES = [APIC_CODE_FORBIDDEN, ]


# Info about a Managed Object's relative name (RN) and container.
class ManagedObjectName(collections.namedtuple('MoPath',
                                               ['container', 'rn_fmt',
                                                'can_create', 'name_fmt'])):
    def __new__(cls, container, rn_fmt, can_create=True, name_fmt=None):
        return super(ManagedObjectName, cls).__new__(cls, container, rn_fmt,
                                                     can_create, name_fmt)


class ManagedObjectClass(object):

    """Information about a Managed Object (MO) class.

    Constructs and keeps track of the distinguished name (DN) and relative
    name (RN) of a managed object (MO) class. The DN is the RN of the MO
    appended to the recursive RNs of its containers, i.e.:
        DN = uni/container-RN/.../container-RN/object-RN

    Also keeps track of whether the MO can be created in the APIC, as some
    MOs are read-only or used for specifying relationships.
    """
    scope = ''
    supported_mos = {
        'fvTenant': ManagedObjectName(None, 'tn-%(name)s', name_fmt='__%s'),
        'fvBD': ManagedObjectName('fvTenant', 'BD-%(name)s', name_fmt='%s'),
        'fvRsBd': ManagedObjectName('fvAEPg', 'rsbd'),
        'fvSubnet': ManagedObjectName('fvBD', 'subnet-[%s]'),
        'fvCtx': ManagedObjectName('fvTenant', 'ctx-%(name)s',
                                   name_fmt='__%s'),
        'fvRsCtx': ManagedObjectName('fvBD', 'rsctx'),
        'fvAp': ManagedObjectName('fvTenant', 'ap-%s'),
        'fvAEPg': ManagedObjectName('fvAp', 'epg-%s'),
        'fvRsProv': ManagedObjectName('fvAEPg', 'rsprov-%s'),
        'fvRsCons': ManagedObjectName('fvAEPg', 'rscons-%s'),
        'fvRsConsIf': ManagedObjectName('fvAEPg', 'rsconsif-%s'),
        'fvRsDomAtt': ManagedObjectName('fvAEPg', 'rsdomAtt-[%s]'),
        'fvRsPathAtt': ManagedObjectName('fvAEPg', 'rspathAtt-[%s]'),

        'vzAny': ManagedObjectName('fvCtx', 'any'),
        'vzRsAnyToCons': ManagedObjectName('vzAny', 'rsanyToCons-%s'),
        'vzRsAnyToProv': ManagedObjectName('vzAny', 'rsanyToProv-%s'),
        'vzBrCP': ManagedObjectName('fvTenant', 'brc-%s'),
        'vzSubj': ManagedObjectName('vzBrCP', 'subj-%s'),
        'vzFilter': ManagedObjectName('fvTenant', 'flt-%s'),
        'vzRsFiltAtt': ManagedObjectName('vzSubj', 'rsfiltAtt-%s'),
        'vzEntry': ManagedObjectName('vzFilter', 'e-%s'),
        'vzInTerm': ManagedObjectName('vzSubj', 'intmnl'),
        'vzRsFiltAtt__In': ManagedObjectName('vzInTerm', 'rsfiltAtt-%s'),
        'vzOutTerm': ManagedObjectName('vzSubj', 'outtmnl'),
        'vzRsFiltAtt__Out': ManagedObjectName('vzOutTerm', 'rsfiltAtt-%s'),
        'vzRsSubjFiltAtt': ManagedObjectName('vzSubj', 'rssubjFiltAtt-%s'),
        'vzCPIf': ManagedObjectName('fvTenant', 'cif-%s'),
        'vzRsIf': ManagedObjectName('vzCPIf', 'rsif'),

        'l3extOut': ManagedObjectName('fvTenant', 'out-%(name)s',
                                      name_fmt='__%s'),
        'l3extRsEctx': ManagedObjectName('l3extOut', 'rsectx'),
        'l3extLNodeP': ManagedObjectName('l3extOut', 'lnodep-%s'),
        'l3extRsNodeL3OutAtt': ManagedObjectName('l3extLNodeP',
                                                 'rsnodeL3OutAtt-[%s]'),
        'ipRouteP': ManagedObjectName('l3extRsNodeL3OutAtt', 'rt-[%s]'),
        'ipNexthopP': ManagedObjectName('ipRouteP', 'nh-[%s]'),
        'l3extLIfP': ManagedObjectName('l3extLNodeP', 'lifp-%s'),
        'l3extRsPathL3OutAtt': ManagedObjectName('l3extLIfP',
                                                 'rspathL3OutAtt-[%s]'),
        'l3extInstP': ManagedObjectName('l3extOut', 'instP-%(name)s',
                                        name_fmt='__%s'),
        'fvRsCons__Ext': ManagedObjectName('l3extInstP', 'rscons-%s'),
        'fvRsProv__Ext': ManagedObjectName('l3extInstP', 'rsprov-%s'),
        'fvCollectionCont': ManagedObjectName('fvRsCons', 'collectionDn-[%s]'),
        'l3extSubnet': ManagedObjectName('l3extInstP', 'extsubnet-[%s]'),

        'physDomP': ManagedObjectName(None, 'phys-%s'),

        'infraInfra': ManagedObjectName(None, 'infra'),
        'infraNodeP': ManagedObjectName('infraInfra', 'nprof-%(name)s',
                                        name_fmt='__%s'),
        'infraLeafS': ManagedObjectName('infraNodeP', 'leaves-%s-typ-%s'),
        'infraNodeBlk': ManagedObjectName('infraLeafS', 'nodeblk-%s'),
        'infraRsAccPortP': ManagedObjectName('infraNodeP', 'rsaccPortP-[%s]'),
        'infraRsAccNodePGrp': ManagedObjectName('infraLeafS', 'rsaccNodePGrp'),
        'infraAccPortP': ManagedObjectName('infraInfra',
                                           'accportprof-%(name)s',
                                           name_fmt='__%s'),
        'infraHPortS': ManagedObjectName('infraAccPortP', 'hports-%s-typ-%s'),
        'infraPortBlk': ManagedObjectName('infraHPortS', 'portblk-%s'),
        'infraRsAccBaseGrp': ManagedObjectName('infraHPortS', 'rsaccBaseGrp'),
        'infraFuncP': ManagedObjectName('infraInfra', 'funcprof'),
        'infraAccNodePGrp': ManagedObjectName('infraFuncP', 'accnodepgrp-%s'),
        'infraAccPortGrp': ManagedObjectName('infraFuncP', 'accportgrp-%s'),
        'infraRsAttEntP': ManagedObjectName('infraAccPortGrp', 'rsattEntP'),

        'infraConnNodeS': ManagedObjectName('infraRsAttEntP',
                                            'nodes-selector%s'),
        'infraConnNodeBlk': ManagedObjectName('infraConnNodeS',
                                              'nodeblk-block1'),
        'infraRsConnPortS': ManagedObjectName('infraConnNodeS',
                                              'rsconnPortS-[%s]'),
        'infraHConnPortS': ManagedObjectName(
            'infraRsAttEntP', 'hports-selector%sLeafPorts-typ-%s'),
        'infraConnPortBlk': ManagedObjectName('infraHConnPortS',
                                              'portblk-block1'),

        'infraAttEntityP': ManagedObjectName('infraInfra', 'attentp-%(name)s',
                                             name_fmt='__%s'),
        'infraProvAcc': ManagedObjectName('infraAttEntityP', 'provacc'),
        'infraRsDomP': ManagedObjectName('infraAttEntityP', 'rsdomP-[%s]'),
        'infraRsVlanNs__phys': ManagedObjectName('physDomP', 'rsvlanNs'),
        'infraRsVlanNs__vmm': ManagedObjectName('vmmDomP', 'rsvlanNs'),
        'infraRsVxlanNs': ManagedObjectName('physDomP', 'rsvxlanNs'),
        'infraAccBndlGrp': ManagedObjectName('infraFuncP', 'accbundle-%s'),
        'infraRsAttEntP2': ManagedObjectName('infraAccBndlGrp', 'rsattEntP'),
        'infraRsLacpPol': ManagedObjectName('infraAccBndlGrp', 'rslacpPol'),
        'lacpLagPol': ManagedObjectName('infraInfra', 'lacplagp-%s'),

        'fvnsVlanInstP': ManagedObjectName('infraInfra', 'vlanns-[%s]-%s'),
        'fvnsEncapBlk__vlan': ManagedObjectName('fvnsVlanInstP',
                                                'from-%s-to-%s'),
        'fvnsVxlanInstP': ManagedObjectName('infraInfra', 'vxlanns-%s'),
        'fvnsEncapBlk__vxlan': ManagedObjectName('fvnsVxlanInstP',
                                                 'from-%s-to-%s'),

        # Fabric
        'fabricInst': ManagedObjectName(None, 'fabric', False),
        'bgpInstPol': ManagedObjectName('fabricInst', 'bgpInstP-%(name)s',
                                        name_fmt='%s'),
        'bgpRRP': ManagedObjectName('bgpInstPol', 'rr'),
        'bgpRRNodePEp': ManagedObjectName('bgpRRP', 'node-%s'),
        'bgpAsP': ManagedObjectName('bgpInstPol', 'as'),

        'fabricFuncP': ManagedObjectName('fabricInst', 'funcprof', False),
        'fabricPodPGrp': ManagedObjectName('fabricFuncP', 'podpgrp-%s'),
        'fabricRsPodPGrpBGPRRP': ManagedObjectName('fabricPodPGrp',
                                                   'rspodPGrpBGPRRP'),

        'fabricPodP': ManagedObjectName('fabricInst', 'podprof-default'),
        'fabricPodS__ALL': ManagedObjectName('fabricPodP', 'pods-%s-typ-ALL'),
        'fabricRsPodPGrp': ManagedObjectName('fabricPodS__ALL', 'rspodPGrp'),

        # Read-only
        'fabricTopology': ManagedObjectName(None, 'topology', False),
        'fabricPod': ManagedObjectName('fabricTopology', 'pod-%s', False),
        'fabricPathEpCont': ManagedObjectName('fabricPod', 'paths-%s', False),
        'fabricPathEp': ManagedObjectName('fabricPathEpCont', 'pathep-%s',
                                          False),
        'fabricNode': ManagedObjectName('fabricPod', 'node-%s', False),
        'vmmProvP': ManagedObjectName(None, 'vmmp-OpenStack', False),
        'vmmDomP': ManagedObjectName('vmmProvP', 'dom-%s'),
        'vmmUsrAccP': ManagedObjectName('vmmDomP', 'usracc-%s'),
        'vmmCtrlrP': ManagedObjectName('vmmDomP', 'ctrlr-%s'),
        'vmmRsVxlanNs': ManagedObjectName('vmmCtrlrP', 'rsvxlanNs'),
        'vmmRsDomMcastAddrNs': ManagedObjectName('vmmDomP',
                                                 'rsdomMcastAddrNs'),

        'fvnsMcastAddrInstP': ManagedObjectName('infraInfra', 'maddrns-%s'),
        'fvnsMcastAddrBlk': ManagedObjectName('fvnsMcastAddrInstP',
                                              'fromaddr-[%s]-toaddr-[%s]'),
        'vmmRsAcc': ManagedObjectName('vmmCtrlrP', 'rsacc'),
    }

    # The ManagedObjects specified below will not be scoped whenever
    # The input parameters match the specified argument
    scope_exceptions = {
        'fvTenant': [('common',)],
    }

    # Note(Henry): The use of a mutable default argument _inst_cache is
    # intentional. It persists for the life of MoClass to cache instances.
    # noinspection PyDefaultArgument
    def __new__(cls, mo_class, _inst_cache={}):
        """Ensure we create only one instance per mo_class."""
        try:
            return _inst_cache[mo_class]
        except KeyError:
            new_inst = super(ManagedObjectClass, cls).__new__(cls)
            new_inst.__init__(mo_class)
            _inst_cache[mo_class] = new_inst
            return new_inst

    def __init__(self, mo_class):
        self.klass = mo_class
        self.klass_name = mo_class.split('__')[0]
        if (self.klass_name[-1:] == '2'):
            self.klass_name = self.klass_name[:-1]
        mo = self.supported_mos[mo_class]
        self.container = mo.container
        if mo.name_fmt:
            self.rn_fmt = mo.rn_fmt % {'name': mo.name_fmt}
            self.name_fmt = mo.name_fmt
        else:
            self.rn_fmt = self.name_fmt = mo.rn_fmt
        self.dn_fmt, self.params = self._dn_fmt()
        self.dn_param_count = self.dn_fmt.count('%s')
        self.rn_param_count = self.rn_fmt.count('%s')
        self.can_create = self.rn_param_count and mo.can_create

    def _dn_fmt(self):
        """Build the distinguished name format using container and RN.

        DN = uni/container-RN/.../container-RN/object-RN

        Also make a list of the required parameters.
        Note: Call this method only once at init.
        """
        param = [self]
        if self.container:
            container = ManagedObjectClass(self.container)
            dn_fmt = '%s/%s' % (container.dn_fmt, self.rn_fmt)
            params = container.params + param
            return dn_fmt, params
        return 'uni/%s' % self.rn_fmt, param

    def _scope(self, fmt, *params):
        if ManagedObjectClass.scope_exceptions:
            exc = ManagedObjectClass.scope_exceptions.get(self.klass)
            res = fmt.replace(
                '__', '' if exc and params in exc else
                ManagedObjectClass.scope)
        else:
            res = fmt.replace('__', '')
        return res % params

    def dn(self, *params):
        """Return the distinguished name for a managed object."""
        dn = ['uni']
        for part in self.params:
            dn.append(part.rn(*params[:part.rn_param_count]))
            params = params[part.rn_param_count:]
        return '/'.join(dn)

    def rn(self, *params):
        """Return the distinguished name for a managed object."""
        return self._scope(self.rn_fmt, *params)

    def name(self, *params):
        """Return the name for a managed object."""
        return self._scope(self.name_fmt, *params)


class ApicSession(object):

    """Manages a session with the APIC."""

    def __init__(self, hosts, usr, pwd, ssl):
        protocol = 'https' if ssl else 'http'
        self.api_base = collections.deque(['%s://%s/api' % (protocol, host)
                                           for host in hosts])
        self.session = requests.Session()
        self.session_deadline = 0
        self.session_timeout = 0
        self.cookie = {}

        # Log in
        self.authentication = None
        self.username = None
        self.password = None
        if usr and pwd:
            self.login(usr, pwd)
        # Init last call to current time
        self.last_call = time.time()
        # 30 ms sleep time
        self.sleep = SLEEP_TIME

    def _do_request(self, request, url, **kwargs):
        """Use this method to wrap all the http requests."""
        for x in range(len(self.api_base)):
            try:
                return request(self.api_base[0] + url, verify=False, **kwargs)
            except FALLBACK_EXCEPTIONS as ex:
                LOG.debug(('%s, falling back to a '
                          'new address'), ex.message)
                self.api_base.rotate(-1)
                LOG.debug(('New controller address: %s '), self.api_base[0])
        return request(self.api_base[0] + url, **kwargs)

    @staticmethod
    def _make_data(key, **attrs):
        """Build the body for a msg out of a key and some attributes."""
        return json.dumps({key: {'attributes': attrs}})

    def _api_url(self, api):
        """Create the URL for a generic API."""
        return '/%s.json' % api

    def _mo_url(self, mo, *args):
        """Create a URL for a MO lookup by DN."""
        dn = mo.dn(*args)
        return '/mo/%s.json' % dn

    def _qry_url(self, mo):
        """Create a URL for a query lookup by MO class."""
        return '/class/%s.json' % mo.klass_name

    def _subtree_url(self, mo, *args, **kwargs):
        cfilter = kwargs.get('cfilter')
        return self._mo_url(mo, *args) + \
            '?query-target=children&%srsp-subtree=full' % \
            ('target-subtree-class=' + cfilter + '&' if cfilter else '')

    def _bulid_target_filter(self, mo, **kwargs):
        """Creates an 'and(eq(), eq(), ...)' filter for requests."""
        filt = ', '.join(['eq(%s.%s, \"%s\")' %
                          (mo.klass_name, key, kwargs[key]) for key in kwargs])
        return '' if not filt else 'query-target-filter=and(%s)' % filt

    def _check_session(self):
        """Check that we are logged in and ensure the session is active."""
        if not self.authentication:
            raise cexc.ApicSessionNotLoggedIn
        if time.time() > self.session_deadline:
            self.refresh()

    def _send(self, request, url, data=None, refreshed=None, accepted=None,
              sleep_offset=0):
        """Send a request and process the response."""
        curr_call = time.time()
        try:
            time.sleep((self.sleep + sleep_offset) -
                       (curr_call - self.last_call))
        except IOError:
            # Negative sleep value
            pass
        if data is None:
            response = self._do_request(request, url, cookies=self.cookie)
        else:
            response = self._do_request(request, url, data=data,
                                        cookies=self.cookie)
        self.last_call = time.time()
        if response is None:
            raise cexc.ApicHostNoResponse(url=url)
        # Every request refreshes the timeout
        self.session_deadline = time.time() + self.session_timeout
        if data is None:
            request_str = url
        else:
            request_str = '%s, data=%s' % (url, data)
            LOG.debug(("data = %s"), data)
        # imdata is where the APIC returns the useful information
        imdata = response.json().get('imdata')
        LOG.debug(("Response: %s"), imdata)
        if response.status_code != requests.codes.ok:
            try:
                err_code = imdata[0]['error']['attributes']['code']
                err_text = imdata[0]['error']['attributes']['text']
            except (IndexError, KeyError):
                err_code = '[code for APIC error not found]'
                err_text = '[text for APIC error not found]'
            # If invalid token then re-login and retry once
            if not refreshed and (err_code in REFRESH_CODES):
                self.login()
                return self._send(request, url, data=data, refreshed=True)
            if not accepted and response.status_code == 202:
                # The APIC queue is full, slow down significantly
                return self._send(request, url, data=data, accepted=True,
                                  sleep_offset=SLEEP_ON_FULL_QUEUE)
            raise cexc.ApicResponseNotOk(request=request_str,
                                         status=response.status_code,
                                         reason=response.reason,
                                         err_text=err_text, err_code=err_code)
        return imdata

    # REST requests

    def get_data(self, request):
        """Retrieve generic data from the server."""
        self._check_session()
        url = self._api_url(request)
        return self._send(self.session.get, url)

    def get_mo(self, mo, *args):
        """Retrieve a managed object by its distinguished name."""
        self._check_session()
        url = self._mo_url(mo, *args) + '?query-target=self'
        return self._send(self.session.get, url)

    def get_mo_subtree(self, mo, *args, **kwargs):
        self._check_session()
        url = self._subtree_url(mo, *args, **kwargs)
        return self._send(self.session.get, url)

    def list_mo(self, mo, **kwargs):
        """Retrieve the list of managed objects for a class."""
        self._check_session()
        url = self._qry_url(mo) + '?' + self._bulid_target_filter(mo, **kwargs)
        return self._send(self.session.get, url)

    def post_data(self, request, data):
        """Post generic data to the server."""
        self._check_session()
        url = self._api_url(request)
        return self._send(self.session.post, url, data=data)

    def post_mo(self, mo, *params, **data):
        """Post data for a managed object to the server."""
        self._check_session()
        url = self._mo_url(mo, *params)
        data = self._make_data(mo.klass_name, **data)
        return self._send(self.session.post, url, data=data)

    def post_body(self, mo, data, *params):
        """Post mo with pre made body."""
        self._check_session()
        url = self._mo_url(mo, *params)
        return self._send(self.session.post, url, data=data)

    def delete_mo(self, mo, *params):
        self._check_session()
        url = self._mo_url(mo, *params)
        return self._send(self.session.delete, url)

    def GET(self, url, data=None):
        return self._send(self.session.get, url, data=data)

    def POST(self, url, data=None):
        return self._send(self.session.post, url, data=data)

    def DELETE(self, url, data=None):
        return self._send(self.session.delete, url, data=data)

    def delete_class(self, klass):
        nodes = self.GET('/node/class/%s.json' % klass)
        for node in nodes:
            dn = node[klass]['attributes']['dn']
            try:
                self.DELETE('/node/mo/' + dn + '.json')
            except Exception as e:
                LOG.debug(e)

    # Session management

    def _save_cookie(self, request, response):
        """Save the session cookie and its expiration time."""
        imdata = response.json().get('imdata')
        if response.status_code == requests.codes.ok:
            attributes = imdata[0]['aaaLogin']['attributes']
            try:
                self.cookie = {'APIC-Cookie': attributes['token']}
            except KeyError:
                raise cexc.ApicResponseNoCookie(request=request)
            timeout = int(attributes['refreshTimeoutSeconds'])
            LOG.debug("APIC session will expire in %d seconds", timeout)
            # Give ourselves a few seconds to refresh before timing out
            self.session_timeout = timeout - 5
            self.session_deadline = time.time() + self.session_timeout
        else:
            attributes = imdata[0]['error']['attributes']
        return attributes

    def login(self, usr=None, pwd=None):
        """Log in to controller. Save user name and authentication."""
        usr = usr or self.username
        pwd = pwd or self.password
        name_pwd = self._make_data('aaaUser', name=usr, pwd=pwd)
        url = self._api_url('aaaLogin')
        self.cookie = {}

        try:
            response = self._do_request(self.session.post, url, data=name_pwd,
                                        timeout=10.0)
        except rexc.Timeout:
            raise cexc.ApicHostNoResponse(url=url)
        attributes = self._save_cookie('aaaLogin', response)
        if response.status_code == requests.codes.ok:
            self.username = usr
            self.password = pwd
            self.authentication = attributes
        else:
            self.authentication = None
            raise cexc.ApicResponseNotOk(request=url,
                                         status=response.status_code,
                                         reason=response.reason,
                                         err_text=attributes['text'],
                                         err_code=attributes['code'])

    def refresh(self):
        """Called when a session has timed out or almost timed out."""
        url = self._api_url('aaaRefresh')
        response = self._do_request(self.session.get, url,
                                    cookies=self.cookie)
        attributes = self._save_cookie('aaaRefresh', response)
        if response.status_code == requests.codes.ok:
            # We refreshed before the session timed out.
            self.authentication = attributes
        else:
            err_code = attributes['code']
            err_text = attributes['text']
            if (err_code == APIC_CODE_FORBIDDEN and
                    err_text.lower().startswith('token was invalid')):
                # This means the token timed out, so log in again.
                LOG.debug(("APIC session timed-out, logging in again."))
                self.login()
            else:
                self.authentication = None
                raise cexc.ApicResponseNotOk(request=url,
                                             status=response.status_code,
                                             reason=response.reason,
                                             err_text=err_text,
                                             err_code=err_code)

    def logout(self):
        """End session with controller."""
        if not self.username:
            self.authentication = None
        if self.authentication:
            data = self._make_data('aaaUser', name=self.username)
            self.post_data('aaaLogout', data=data)
        self.authentication = None


class ManagedObjectAccess(object):

    """CRUD operations on APIC Managed Objects."""

    def __init__(self, session, mo_class):
        self.session = session
        self.mo = ManagedObjectClass(mo_class)

    def _mo_attributes(self, obj_data):
        if (self.mo.klass_name in obj_data and
                'attributes' in obj_data[self.mo.klass_name]):
            return obj_data[self.mo.klass_name]['attributes']

    def create(self, *params, **data):
        result = []
        transaction = data.pop('transaction', None)
        with self.session.transaction(transaction, result) as trs:
            getattr(trs, self.mo.klass).add(*params, **data)
        if result:
            return result[0]

    def update(self, *params, **data):
        return self.create(*params, **data)

    def delete(self, *params, **data):
        result = []
        transaction = data.pop('transaction', None)
        with self.session.transaction(transaction, result) as trs:
            getattr(trs, self.mo.klass).remove(*params)
        if result:
            return result[0]

    def get(self, *params):
        """Return a dict of the MO's attributes, or None."""
        imdata = self.session.get_mo(self.mo, *params)
        if imdata:
            return self._mo_attributes(imdata[0])

    def get_subtree(self, *params, **data):
        return self.session.get_mo_subtree(self.mo, *params, **data)

    def list_all(self, **data):
        imdata = self.session.list_mo(self.mo, **data)
        return filter(None, [self._mo_attributes(obj) for obj in imdata])

    def list_names(self, **data):
        return [obj['name'] for obj in self.list_all(**data)]

    def dn(self, *data):
        return self.mo.dn(*data)

    def rn(self, *data):
        return self.mo.rn(*data)

    def name(self, *data):
        return self.mo.name(*data)


class Transaction(object):
    """API consistent with RestClient class to operate Transactions."""

    def __init__(self, session):
        self.root = None
        self.root_params = []
        self.root_mo = None
        self.session = session

    def __getattr__(self, mo_class):
        if mo_class not in ManagedObjectClass.supported_mos:
            raise cexc.ApicManagedObjectNotSupported(mo_class=mo_class)
        self.__dict__[mo_class] = TransactionBuilder(self, mo_class)
        return self.__dict__[mo_class]

    def init_root(self, mo, *params, **data):
        self.session.renew(mo, *params)
        self.root = TransactionNode(mo.klass_name, mo.rn(*params), **data)
        self.root_params = params
        self.root_mo = mo

    def _is_same_node(self, mo_class, mo_rn, node):
        return (mo_class in node and
                node[mo_class]['attributes'].get('rn') == mo_rn)

    def _append_child(self, parent, mo, *params, **kwargs):
        level = parent[mo.container.split('__')[0]]['children']
        # The object has to be appended at this level
        offset = 0 - mo.rn_param_count
        mo_rn = mo.rn(*params[offset:]) if offset else mo.rn_fmt
        for child in level:
            # Check if the node already exists
            if self._is_same_node(mo.klass_name, mo_rn, child):
                # Update and return the found node
                return child.update_attributes(rn=mo_rn, **kwargs)

        # Node not found, add at this level
        if self.session.renew(mo, *params):
            # Re calculate RN for current MO
            mo_rn = mo.rn(*params[offset:]) if offset else mo.rn_fmt
        curr = TransactionNode(mo.klass_name, mo_rn, **kwargs)
        level.append(curr)
        return curr

    def create_branch(self, mo, *params):
        """Recursively create all container nodes."""
        offset = 0 - mo.rn_param_count
        rn = mo.rn(*params[offset:]) if offset else mo.rn_fmt
        if not mo.container:
            # Tail of recursion
            if not self.root:
                self.init_root(mo, *params)
            elif not self._is_same_node(mo.klass_name, rn, self.root):
                raise cexc.ApicInvalidTransactionMultipleRoot()
            return self.root
        container = ManagedObjectClass(mo.container)
        parent = self.create_branch(container,
                                    *params[:container.dn_param_count])
        # Mo is child of this node
        return self._append_child(parent, mo, *params)

    def commit(self):
        return self.session.post_body(
            self.root_mo, json.dumps(self.root),
            *self.root_params)


class TransactionBuilder(object):
    """Creates a ManagedObject subtree starting from a root."""

    def __init__(self, transaction, mo_class):
        self.trs = transaction
        self.mo = ManagedObjectClass(mo_class)

    def add(self, *args, **kwargs):
        node = self.trs.create_branch(self.mo, *args)
        node.update_attributes(**kwargs)

    def remove(self, *args):
        node = self.trs.create_branch(self.mo, *args)
        node.update_attributes(status='deleted')


class TransactionNode(dict):

    def __init__(self, mo_class, mo_rn, **kwargs):
        dict.__init__(self)
        self.mo_class = mo_class
        self.mo_rn = mo_rn
        self.attributes = {"rn": mo_rn}
        self.children = []
        self.update_attributes(**kwargs)
        self[mo_class] = {"attributes": self.attributes,
                          "children": self.children}

    def update_attributes(self, **kwargs):
        for key in kwargs:
            self.attributes[str(key)] = str(kwargs[key])
        return self


class RestClient(ApicSession):

    """APIC REST client for OpenStack Neutron.

    Can be used to create objects singularly or to build more complicated
    transactions.
    """

    def __init__(self, log, system_id, hosts, usr=None, pwd=None, ssl=True,
                 scope_names=True, renew_names=True):
        """Establish a session with the APIC."""
        if not scope_names:
            ManagedObjectClass.scope_exceptions = None
        global LOG
        LOG = log.getLogger(__name__)
        super(RestClient, self).__init__(hosts, usr, pwd, ssl)
        ManagedObjectClass.scope = '_' + system_id + '_'
        self.dn_manager = DNManager()
        self.renew_names = renew_names

    def __getattr__(self, mo_class):
        """Add supported MOs as properties on demand."""
        if mo_class not in ManagedObjectClass.supported_mos:
            raise cexc.ApicManagedObjectNotSupported(mo_class=mo_class)
        self.__dict__[mo_class] = ManagedObjectAccess(self, mo_class)
        return self.__dict__[mo_class]

    def renew(self, mo, *params):
        """Verify that an object exists and renew it if needed."""
        if self.renew_names:
            if mo.rn_fmt.count("%s") > 0:
                renewable = [x for x in params[(0 - mo.rn_fmt.count("%s")):]
                             if hasattr(x, 'uid')]
                if renewable:
                    current = self.get_mo(mo, *params)
                    if not current:
                        try:
                            map(lambda y: y.renew(), renewable)
                            return True
                        except Exception as e:
                            LOG.error(e.message)
        return False

    @contextlib.contextmanager
    def transaction(self, transaction=None, ph=None):
        if not transaction:
            transaction = Transaction(self)
            yield transaction
            if transaction.root:
                result = transaction.commit()
                if ph is not None:
                    ph.append(result)
        else:
            # Only the top owner will commit the transaction
            yield transaction


class DNManager(object):
    """ DN Manager.

    Utility methods for dn management, such us param decomposition.
    """
    class InvalidNameFormat(Exception):
        pass

    nice_to_rn = {'context': 'fvCtx',
                  'bridge_domain': 'fvBD',
                  'endpoint_group': 'fvAEPg',
                  'contract': 'vzBrCP'}

    def __getattr__(self, item):
        if item.startswith('decompose_'):
            if item[len('decompose_'):] in DNManager.nice_to_rn:
                def decompose_wrapper(dn):
                    return self._decompose_mo(dn, item[len('decompose_'):])
                return decompose_wrapper

        raise AttributeError

    def _decompose(self, dn, mo):
        if not dn:
            raise DNManager.InvalidNameFormat()
        fmt = (mo.rn_fmt.replace('__', '').replace('%s', '(.+)').
               replace('[', '\[').replace(']', '\]'))

        split = dn.split('/')
        param = re.findall(fmt, split[-1])
        if not param or len(param) != mo.rn_param_count:
            raise DNManager.InvalidNameFormat()
        if mo.container:
            return self._decompose(
                dn[:-(len(split[-1]) + 1)],
                ManagedObjectClass(mo.container)) + param
        else:
            if len(split) > 2:
                raise DNManager.InvalidNameFormat()
            if len(split) == 2 and split[0] != 'uni':
                raise DNManager.InvalidNameFormat()
            return param

    def _decompose_mo(self, dn, nice):
        try:
            return self._decompose(
                dn, ManagedObjectClass(DNManager.nice_to_rn[nice]))
        except DNManager.InvalidNameFormat:
            return None
