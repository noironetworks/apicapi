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
# @author: Ivar Lazzaro (ivar-lazzaro), Cisco Systems Inc.

import setuptools


setuptools.setup(
    name="apicapi",
    version="1.0.4",
    packages=setuptools.find_packages(exclude=["*.tests", "*.tests.*",
                                               "tests.*", "tests"]),
    author="Cisco Systems, Inc.",
    author_email="apicapi@noironetworks.com",
    url="http://github.com/noironetworks/apicapi/",
    license="http://www.apache.org/licenses/LICENSE-2.0",
    description="This library provides an interface to the APIC REST api.",
    entry_points={
        'console_scripts': [
            'apic-cleanup = apicapi.tools.cleanup:main',
            'apic-route-reflector = apicapi.tools.reflector:main']
    }
)
