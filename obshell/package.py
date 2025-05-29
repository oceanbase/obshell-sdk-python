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

def search_package(name: str, version: str = None, release: str = None):
    '''
        Search for a package in the configured mirrors.  
        This function searches for a package with the given name, and optionally a specific version and release, 
        in the pre-configured list of mirrors. If the package is found in any of the mirrors, it returns a list of
        RemotePackageInfo objects. If the package is not found, it returns an empty list.
        
        :param name: The name of the package to search for.
        :param version: The version of the package to search for (optional).
        :param release: The release of the package to search for (optional).
        
        :return: A list of RemotePackageInfo objects representing the found packages, or an empty list if not found. """
    '''
    from obshell.mirror import MIRRORS
    for mirror in MIRRORS:
        packages = mirror._search(name, version, release)
        if packages:
            return packages
    raise Exception(f"No such package: {name}-{version}-{release}")


def download_package(dest_dir: str, name: str, version: str = None, release: str = None):
    '''
        Download a package from the configured mirrors to a specified directory. 
        This function searches for a package with the given name, and optionally a specific version and release,
        in the pre-configured list of mirrors. If the package is found, it downloads the first matching package to the 
        specified destination directory. If the package is not found in any of the mirrors, it raises an exception.
        
        :param dest_dir: The directory where the package will be downloaded.
        :param name: The name of the package to download.
        :param version: The version of the package to download (optional).
        :param release: The release of the package to download (optional).
        
        :raises Exception: If no matching package is found in any of the mirrors.
    '''
    from obshell.mirror import MIRRORS
    for mirror in MIRRORS:
        packages = mirror._search(name, version, release)
        if packages:
            package = packages[0]
            return mirror._download_package(package, dest_dir)
    raise Exception(f"No such package: {name}-{version}-{release}")

