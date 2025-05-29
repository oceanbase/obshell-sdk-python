# coding: utf-8
# Copyright (c) 2024 OceanBase.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import gzip
from typing import List, Optional
import xml.etree.ElementTree as ET

import requests

from obshell.arch import getBaseArch
from obshell.pkg import PackageInfo, Version, Release

try:
    import locale
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
except Exception as e:
    pass

REMOTE_REPOMD_FILE = "/repodata/repomd.xml"
PRIMARY_REPOMD_TYPE = "primary"

X86_64 = "x86_64"
AARCH64 = "aarch64"

EL7 = "7"
EL8 = "8"


def ns_cleanup(qn):
    return qn if qn.find('}') == -1 else qn.split('}')[1]


class RepoData(object):

    def __init__(self, elem):
        self.type = None
        self.type = elem.attrib.get('type')
        self.location = (None, None)
        self.checksum = (None,None) # type,value
        self.openchecksum = (None,None) # type,value
        self.timestamp = None
        self.dbversion = None
        self.size      = None
        self.opensize  = None
        self.deltas    = []
        self._parser(elem)
    
    def _parser(self, elem):
        for child in elem:
            child_name = ns_cleanup(child.tag)
            if child_name == 'location':
                relative = child.attrib.get('href')
                base = child.attrib.get('base')
                self.location = (base, relative)
            
            elif child_name == 'checksum':
                csum_value = child.text
                csum_type = child.attrib.get('type')
                self.checksum = (csum_type,csum_value)

            elif child_name == 'open-checksum':
                csum_value = child.text
                csum_type = child.attrib.get('type')
                self.openchecksum = (csum_type, csum_value)
            
            elif child_name == 'timestamp':
                self.timestamp = child.text
            elif child_name == 'database_version':
                self.dbversion = child.text
            elif child_name == 'size':
                self.size = child.text
            elif child_name == 'open-size':
                self.opensize = child.text
            elif child_name == 'delta':
                delta = RepoData(child)
                delta.type = self.type
                self.deltas.append(delta)


class RemotePackageInfo(PackageInfo):

    def __init__(self, elem):
        self.epoch = None
        self.location = (None, None)
        self.checksum = (None,None) # type,value
        self.openchecksum = (None,None) # type,value
        self.time = (None, None)
        self.package_size = None
        super(RemotePackageInfo, self).__init__(None, None, None, None, None, None)
        self._parser(elem)

    @property
    def md5(self):
        return self.checksum[1]

    @md5.setter
    def md5(self, value):
        self.checksum = (self.checksum[0], value)

    def __str__(self):
        url = self.location[1]
        if self.location[0]:
            url = self.location[0] + url
        return url

    def _parser(self, elem):
        for child in elem:
            child_name = ns_cleanup(child.tag)
            if child_name == 'location':
                relative = child.attrib.get('href')
                base = child.attrib.get('base')
                self.location = (base, relative)

            elif child_name == 'checksum':
                csum_value = child.text
                csum_type = child.attrib.get('type')
                self.checksum = (csum_type,csum_value)

            elif child_name == 'open-checksum':
                csum_value = child.text
                csum_type = child.attrib.get('type')
                self.openchecksum = (csum_type, csum_value)

            elif child_name == 'version':
                self.epoch = child.attrib.get('epoch')
                self.set_version(child.attrib.get('ver'))
                self.set_release(child.attrib.get('rel'))

            elif child_name == 'time':
                build = child.attrib.get('build')
                _file = child.attrib.get('file')
                self.time = (int(_file), int(build))

            elif child_name == 'arch':
                self.arch = child.text
            elif child_name == 'name':
                self.name = child.text

            elif child_name == 'size':
                self.size = int(child.attrib.get('installed'))
                self.package_size = int(child.attrib.get('package'))


class Mirror:

    def __init__(self, name: str, url: str, non_lse: Optional[bool] = None):
        self.name = name
        self.url = url
        self.non_lse = non_lse
        self._repomds : List[RepoData] = None
        self._primary_repomd : RepoData = None
        self._packages : List[RemotePackageInfo] = None

    def init_repomds(self) -> RepoData:
        if self._repomds is None:
            url = self.url + REMOTE_REPOMD_FILE
            self._repomds : List[RepoData] = []
            response = requests.get(url)
            response.raise_for_status()  # raises an error for bad responses
            for elem in ET.fromstring(response.content):
                if ns_cleanup(elem.tag) == 'data':
                    self._repomds.append(RepoData(elem))
        return self._repomds
    
    def get_primary_repomd(self) -> RepoData:
        if self._primary_repomd is None:
            for repomd in self.init_repomds():
                if repomd.type == PRIMARY_REPOMD_TYPE:
                    self._primary_repomd = repomd
                    break
        return self._primary_repomd
    
    def get_packages(self) -> List[RemotePackageInfo]:
        if self._packages is None:
            self._packages = []
            repomd = self.get_primary_repomd()
            base_url = repomd.location[0] if repomd.location[0] else self.url
            url = '%s/%s' % (base_url, repomd.location[1])
            response = requests.get(url)
            response.raise_for_status()
            data = gzip.decompress(response.content)
            for elem in ET.fromstring(data):
                if ns_cleanup(elem.tag) == 'package' and elem.attrib.get('type') == 'rpm':
                    self._packages.append(RemotePackageInfo(elem))
        return self._packages

    def get_local_url(self, location: dict) -> str:
        base_url = location.get('base', self.url)
        return base_url + location['href']
    
    def search(self, name: str, version: str = None, release: str = None) -> List[RemotePackageInfo]:
        """
            Search for a package by name, version, and release.
            
            This method searches for packages that match the given name, version, and release information.
            If no matching packages are found, it raises an exception.
            
            Parameters:
                name (str): The name of the package to search for.
                version (str, optional): The version of the package to search for. Defaults to `None`.
                release (str, optional): The release information of the package to search for. Defaults to `None`.
            
            Returns:
            
                List[RemotePackageInfo]: A list of matching packages, represented as `RemotePackageInfo` objects.
                
            Raises:
                Exception: If no matching package is found, an exception is raised with a message indicating
                the requested package name, version, and release.
            
            """
        matchs = self._search(name, version, release)
        if not matchs:
            raise Exception(f"No such package: {name}-{version}-{release}")
        return matchs

    def _search(self, name: str, version: str = None, release: str = None) -> List[RemotePackageInfo]:
        packages = self.get_packages()
        version = Version(version) if version else None
        release = Release(release) if release else None
        matchs : List[RemotePackageInfo] = []
        for package in packages:
            if package.name != name:
                continue
            if version and package.version != version:
                continue
            if release and package.release != release:
                continue
            matchs.append(package)
        return sorted(matchs, key=lambda pkg: (pkg.version, pkg.release, self.non_lse and 'nonlse' in pkg.release), reverse=True)
    
    def download(self, dest_dir: str, name: str, version: str = None, release: str = None) -> str:
        """
            Download a specified package to the destination directory.
        
            This method searches for a package that matches the given name, version, and release information,
            and downloads it to the specified destination directory. The `search` method will raise an
            exception if no matching package is found, so there is no need to explicitly check for matches
            in this function.
        
        Parameters:
            dest_dir (str): The path of the directory to download the file to.
            name (str): The name of the package to be downloaded.
            version (str, optional): The version of the package to be downloaded. Defaults to `None`.
            release (str, optional): The release information of the package to be downloaded. Defaults to `None`.
        
        Returns:
            str: The file path of the downloaded package. 
        
        Exceptions: 
            An exception will be raised by the `search` method if no matching package is found.
        """
        package = self.search(name, version, release)[0]
        return self._download_package(package, dest_dir)
    
    def _download_package(self, package: RemotePackageInfo, dest_dir: str) -> str:
        if not os.path.isabs(dest_dir):
            raise Exception(f"Destination is not an absolute path: {dest_dir}")
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)
        else:
            if not os.path.isdir(dest_dir):
                raise Exception(f"Destination is not a directory: {dest_dir}")
        file_name = package.location[1]
        file_path = os.path.join(dest_dir, file_name)
        base_url = package.location[0] if package.location[0] else self.url
        url = '%s/%s' % (base_url, package.location[1])
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(file_path, 'wb') as f:
            f.write(response.content)
        return file_path


ARCH = getBaseArch()
version = os.popen("ldd --version").read()
match = re.search(r'ldd\s+(\d+\.\d+)', version)
RELEASE = EL8 if match and match.group(1) >= "2.28" else EL7
NON_LSE = ARCH == 'aarch64' and not os.popen("grep atomics /proc/cpuinfo ").read()


class BaseMirror:

    def __init__(self, name: str, base_url: str):
        self.name = name
        self.base_url = base_url

    def get_mirror(self, arch: str, release: str, non_lse: bool = None) -> Mirror:
        url = self.base_url.replace("$releasever", release).replace("$basearch", arch)
        name = self.name.replace("$releasever", release).replace("$basearch", arch)
        mirror = Mirror(name=name, url=url)
        if arch == "aarch64":
            if non_lse is not None:
                mirror.non_lse = non_lse
            else:
                mirror.non_lse = NON_LSE
        return mirror


BASE_COMMUNITY_MIRROR = BaseMirror("OceanBase-community-stable", "https://mirrors.oceanbase.com/oceanbase/community/stable/el/$releasever/$basearch/")
BASE_DEV_KIT_MIRROR = BaseMirror("OceanBase-development-kit", "https://mirrors.oceanbase.com/oceanbase/development-kit/el/$releasever/$basearch/")
COMMUNITY_MIRROR = BASE_COMMUNITY_MIRROR.get_mirror(ARCH, RELEASE)
DEV_KIT_MIRROR = BASE_DEV_KIT_MIRROR.get_mirror(ARCH, RELEASE)
MIRRORS = [COMMUNITY_MIRROR, DEV_KIT_MIRROR]
