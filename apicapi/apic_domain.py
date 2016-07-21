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

from apicapi import exceptions as cexc

# VMM type supported
APIC_VMM_TYPE_OPENSTACK = 'OpenStack'
APIC_VMM_TYPE_VMWARE = 'VMware'
APIC_VMM_TYPES_SUPPORTED = [APIC_VMM_TYPE_OPENSTACK, APIC_VMM_TYPE_VMWARE]

LOG = None


class ApicDomain(object):
    """Apic Domain base class."""

    def __init__(self, apic_system_id, client, log, apic_conf, name, conf,
                 network_config):
        global LOG
        LOG = log.getLogger(__name__)

        self.apic = client
        self._name = name
        self.apic_domain_name = apic_conf.apic_domain_name
        self.apic_system_id = apic_system_id
        self.conf = ApicDomainConfig(apic_conf, conf, self.dn)

        # Parse vlan configuration if any
        self.vlan_ranges = self.conf.vlan_ranges
        self.vlan_ns_name = self.conf.apic_vlan_ns_name
        if not self.vlan_ranges and network_config.get('vlan_ranges'):
            self.vlan_ranges = [':'.join(x.split(':')[-2:]) for x in
                                network_config.get('vlan_ranges')]

        self.encap_mode = self.conf.encap_mode
        if not self.encap_mode:     # guess from other options
            self.encap_mode = 'vlan' if self.vlan_ranges else 'vxlan'
        LOG.info("Encap mode for domain %s is %s", self.name, self.encap_mode)

    @property
    def dn(self):
        return None

    @property
    def name(self):
        return self._name

    def create(self):
        pass

    def _create_vlan_namespace(self):
        # Create VLAN namespace
        vlan_ns_dn = None
        if self.vlan_ranges:
            vlan_ns_name = self.vlan_ns_name
            vlan_range = self.vlan_ranges[0]
            (vlan_min, vlan_max) = vlan_range.split(':')
            vlan_ns_dn = self._ensure_vlan_ns_created_on_apic(
                vlan_ns_name, vlan_min, vlan_max)
        return vlan_ns_dn

    def _ensure_vlan_ns_created_on_apic(self, name, vlan_min, vlan_max,
                                       scope='static', transaction=None):
        """Creates a static VLAN namespace with the given vlan range."""

        ns_args = (name, scope)
        vlan_min = 'vlan-' + vlan_min
        vlan_max = 'vlan-' + vlan_max
        ns_blk_args = ns_args + (vlan_min, vlan_max)
        ns_kw_args = {
            'name': 'encap',
            'from': vlan_min,
            'to': vlan_max
        }
        with self.apic.transaction(transaction) as trs:
            self.apic.fvnsVlanInstP.create(*ns_args, transaction=trs)
            self.apic.fvnsEncapBlk__vlan.create(*ns_blk_args,
                                                transaction=trs,
                                                **ns_kw_args)
        return self.apic.fvnsVlanInstP.dn(*ns_args)


class VmDomain(ApicDomain):
    """APIC VMM Domain."""

    def __init__(self, apic_system_id, client, log, apic_conf, vmdom_name,
                 vmdom_conf, network_config):

        temp_conf = ApicDomainConfig(apic_conf, vmdom_conf, None)
        # Set VMM type
        if (APIC_VMM_TYPE_OPENSTACK.lower() ==
                temp_conf.apic_vmm_type.lower()):
            self.vmm_type = APIC_VMM_TYPE_OPENSTACK
        elif (APIC_VMM_TYPE_VMWARE.lower() ==
              temp_conf.apic_vmm_type.lower()):
            self.vmm_type = APIC_VMM_TYPE_VMWARE
        else:
            self.vmm_type = temp_conf.apic_vmm_type

        self.vmm_controller_host = temp_conf.vmm_controller_host
        super(VmDomain, self).__init__(apic_system_id, client, log, apic_conf,
                                       vmdom_name, vmdom_conf, network_config)

    @property
    def dn(self):
        return self.apic.vmmDomP.dn(self.vmm_type, self.name)

    def create(self):
        LOG.info("Creating VMM Domain %s", self.dn)
        vlan_ns_dn = self._create_vlan_namespace()
        # Create VMM domain
        vmm_name = self.name
        if APIC_VMM_TYPE_VMWARE == self.vmm_type:
            vmm_dom = self.apic.vmmDomP.get(APIC_VMM_TYPE_VMWARE, vmm_name)
            if vmm_dom is None:
                raise cexc.ApicVmwareVmmDomainNotConfigured(name=vmm_name)

            return
        elif APIC_VMM_TYPE_OPENSTACK != self.vmm_type:
            raise cexc.ApicVmmTypeNotSupported(
                type=self.vmm_type, list=APIC_VMM_TYPES_SUPPORTED)

        self._ensure_vmm_domain_created_on_apic(
                APIC_VMM_TYPE_OPENSTACK, vmm_name,
                self.conf.openstack_user,
                self.conf.openstack_password,
                self.conf.multicast_address, vlan_ns_dn=vlan_ns_dn)

        # Create Multicast namespace for VMM in vxlan mode
        if self.encap_mode == "vxlan":
            mcast_name = self.conf.apic_multicast_ns_name
            mcast_range = self.conf.mcast_ranges[0]
            (mcast_min, mcast_max) = mcast_range.split(':')[-2:]
            self._ensure_mcast_ns_created_on_apic(
                APIC_VMM_TYPE_OPENSTACK, vmm_name, mcast_name,
                mcast_min, mcast_max)

        # Attempt to set encapMode on DomP...catch and ignore exceptions
        # as older APIC versions do not support the field
        vmm_dn = self.apic.vmmDomP.dn(self.vmm_type, vmm_name)
        try:
            self.apic.vmmDomP.update(self.vmm_type, vmm_name, dn=vmm_dn,
                                     encapMode=self.encap_mode)
        except cexc.ApicResponseNotOk as ex:
            # Ignore as older APIC versions will not support
            # vmmDomP.encapMode
            LOG.info("Expected failure for APIC 1.1 %s", ex)

        # Attempt to set prefEncapMode on DomP...catch and ignore exceptions
        # as older APIC versions do not support the field
        try:
            self.apic.vmmDomP.update(self.vmm_type, vmm_name, dn=vmm_dn,
                                     prefEncapMode=self.encap_mode)
        except cexc.ApicResponseNotOk as ex:
            # Ignore as older APIC versions will not support
            # vmmDomP.prefEncapMode
            LOG.info("Expected failure for APIC versions before 2.1 %s", ex)

    def _ensure_vmm_domain_created_on_apic(self, vmm_type, vmm_name, usr, pwd,
                                           multicast_addr, vlan_ns_dn=None,
                                           transaction=None):
        """Create vmm domain."""

        with self.apic.transaction(transaction) as trs:
            self.apic.vmmDomP.create(
                vmm_type, vmm_name, enfPref="sw", mode="ovs",
                mcastAddr=multicast_addr,
                transaction=trs)
            self.apic.vmmUsrAccP.create(vmm_type, vmm_name, vmm_name, usr=usr,
                                        pwd=pwd, transaction=trs)
            usracc_dn = self.apic.vmmUsrAccP.dn(vmm_type, vmm_name, vmm_name)
            self.apic.vmmCtrlrP.create(
                vmm_type, vmm_name, vmm_name, scope="openstack",
                rootContName=vmm_name, hostOrIp=self.vmm_controller_host,
                mode="ovs", transaction=trs)
            self.apic.vmmRsAcc.create(vmm_type, vmm_name, vmm_name,
                                      tDn=usracc_dn, transaction=trs)
            if self.encap_mode == 'vlan' and vlan_ns_dn:
                self.apic.infraRsVlanNs__vmm.create(
                    vmm_type, vmm_name, tDn=vlan_ns_dn, transaction=trs)

    def _ensure_mcast_ns_created_on_apic(self, vmm_type, vmm_name,
                                         name, mcast_min, mcast_max,
                                         transaction=None):
        """Creates a Multicast namespace with the given vni range."""

        ns_args = (name,)
        dn = self.apic.fvnsMcastAddrInstP.dn(*ns_args)
        ns_blk_args = name, mcast_min, mcast_max
        ns_kw_args = {
            'from': mcast_min,
            'to': mcast_max
        }
        with self.apic.transaction(transaction) as trs:
            self.apic.fvnsMcastAddrInstP.create(*ns_args, transaction=trs)
            self.apic.fvnsMcastAddrBlk.create(*ns_blk_args,
                                              transaction=trs,
                                              **ns_kw_args)
        self.apic.vmmRsDomMcastAddrNs.create(vmm_type, vmm_name, tDn=dn)
        return dn

    def _ensure_vlan_ns_created_on_apic(self, name, vlan_min, vlan_max,
                                        scope='dynamic', transaction=None):
        return super(VmDomain, self)._ensure_vlan_ns_created_on_apic(
            name, vlan_min, vlan_max, scope=scope, transaction=transaction)


class PhysDom(ApicDomain):
    """APIC Physical Domain."""

    def __init__(self, apic_system_id, client, log, apic_conf, physdom_name,
                 physdom_conf, network_config):
        super(PhysDom, self).__init__(apic_system_id, client, log, apic_conf,
                                      physdom_name, physdom_conf,
                                      network_config)

    @property
    def dn(self):
        return self.apic.physDomP.dn(self.name)

    def create(self):
        LOG.info("Creating Physical Domain %s", self.dn)
        vlan_ns_dn = self._create_vlan_namespace()
        self._ensure_phys_domain_created_on_apic(self.name, vlan_ns_dn)

    def _ensure_phys_domain_created_on_apic(self, phys_name, vlan_ns_dn=None,
                                            transaction=None):
        """Create physical domain.
        Creates the physical domain on the APIC and adds a VLAN
        namespace to that physical domain.
        """
        with self.apic.transaction(transaction) as trs:
            self.apic.physDomP.create(phys_name, transaction=trs)
            if vlan_ns_dn:
                self.apic.infraRsVlanNs__phys.create(
                    phys_name, tDn=vlan_ns_dn, transaction=trs)


class ApicDomainConfig(object):
    """Configuration wrapper for APIC domains.

    This wrapper uses domain specific configuration if any, and falls back to
    global defaults otherwise.
    """

    def __init__(self, apic_conf, domain_conf, domain_dn):
        # APIC conf is a oslo_config object, while domain_conf is a dictionary
        self.apic_conf = apic_conf
        self.domain_conf = domain_conf
        self.domain_dn = domain_dn

    def __getattr__(self, item):
        try:
            result = self.domain_conf[item]
            if LOG:
                LOG.debug("Configuration %(item)s found in per-domain "
                          "config for domain %(dn)s with value %(value)s",
                          {'item': item, 'dn': self.domain_dn,
                           'value': result})
        except KeyError:
            result = getattr(self.apic_conf, item)
            if LOG:
                LOG.debug("Configuration %(item)s found in global "
                          "config for domain %(dn)s with value = %(value)s",
                          {'item': item, 'dn': self.domain_dn,
                           'value': result})
        return result
