#!/usr/bin/python
"""
DTNRM Agent NetTester for initiated paths.
Requirement is to have the gist config in place.
To Install:
    python setup-agent.py build install --force

Copyright 2019 California Institute of Technology
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
Title 			: dtnrm
Author			: Justas Balcas
Email 			: justas.balcas (at) cern.ch
@Copyright		: Copyright (C) 2019 California Institute of Technology
Date			: 2019/06/17
"""
import os
import glob
from setuptools import setup
from setupUtilities import list_packages, get_py_modules
from setupUtilities import getConfig, createDirs
from setupUtilities import createAllDirsFromConfig

CONFIG = None
CONFIG_LOCATION = []
if os.path.isfile('/etc/dtnrm/main.conf'):
    CONFIG_LOCATION.append('/etc/dtnrm/main.conf')
else:
    CONFIG_LOCATION.append('packaging/dtnrm-site-agent/dtnrmagent.conf')

CONFIG = getConfig(CONFIG_LOCATION)
MAINDIR = CONFIG.get('general', 'private_dir')
createAllDirsFromConfig(CONFIG, MAINDIR)
RAWCONFIGS = "%s/%s/" % (MAINDIR, "rawConfigs")
createDirs(RAWCONFIGS)

setup(
    name='DTNRMAgent-NetTester',
    version="0.1",
    long_description="DTN-RM Agent NetTester",
    author="Justas Balcas",
    author_email="justas.balcas@cern.ch",
    url="http://hep.caltech.edu",
    download_url="https://github.com/sdn-sense/dtnrm-nettester-plugin",
    keywords=['DTN-RM', 'system', 'monitor', 'SDN', 'end-to-end'],
    package_dir={'': 'src/python/'},
    packages=['DTNRMNetTester'] + list_packages(['src/python/DTNRMNetTester/']),
    data_files=[("/opt/sense-client", glob.glob("packaging/sense-client/*"))],
    py_modules=get_py_modules(['src/python/DTNRMNetTester']),
)
