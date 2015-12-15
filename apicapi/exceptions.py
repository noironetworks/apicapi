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

"""Exceptions used by Cisco APIC ML2 mechanism driver."""


class ApicException(Exception):
    message = ("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(ApicException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
            self.err_code = kwargs.get('err_code')
        except Exception:
            super(ApicException, self).__init__(self.message)

    def __unicode__(self):
        return unicode(self.msg)


class InvalidConfig(ApicException):
    message = 'Value %(value)s is invalid for config config %(ctype)s: ' \
              '%(reason)s'


class BadRequest(ApicException):
    message = 'Bad %(resource)s request: %(msg)s'


class NotFound(ApicException):
    pass


class NotAuthorized(ApicException):
    message = "Not authorized."


class ApicHostNoResponse(NotFound):
    """No response from the APIC via the specified URL."""
    message = "No response from APIC at %(url)s"


class ApicResponseNotOk(ApicException):
    """A response from the APIC was not HTTP OK."""
    message = ("APIC responded with HTTP status %(status)s: %(reason)s, "
               "Request: '%(request)s', "
               "APIC error code %(err_code)s: %(err_text)s")


class ApicOperationNotSupported(BadRequest):
    pass


class ApicResponseNoCookie(ApicException):
    """A response from the APIC did not contain an expected cookie."""
    message = "APIC failed to provide cookie for %(request)s request"


class ApicSessionNotLoggedIn(NotAuthorized):
    """Attempted APIC operation while not logged in to APIC."""
    message = "Authorized APIC session not established"


class ApicHostNotConfigured(NotAuthorized):
    """The switch and port for the specified host are not configured."""
    message = "The switch and port for host '%(host)s' are not configured"


class ApicManagedObjectNotSupported(ApicException):
    """Attempted to use an unsupported Managed Object."""
    message = "Managed Object '%(mo_class)s' is not supported"


class ApicMultipleVlanRanges(ApicException):
    """Multiple VLAN ranges specified."""
    message = ("Multiple VLAN ranges are not supported in the APIC plugin. "
               "Please specify a single VLAN range. "
               "Current config: '%(vlan_ranges)s'")


class ApicInvalidTransactionMultipleRoot(ApicException):
    """The current transaction has more than one root node."""
    message = "An apic transaction cannot start from multiple root nodes"


class ApicVmwareVmmDomainNotConfigured(ApicException):
    """The VMware VMM domain doesn't exist in APIC."""
    message = "VMware VMM Domain '%(name)s' does not exist in APIC"


class ApicVmmTypeNotSupported(ApicException):
    """The APIC VMM type is not supported at this moment."""
    message = ("VMM type '%(type)s' is not supported. Currently we only "
               "support '%(list)s'.")
