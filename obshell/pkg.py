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
from typing import Dict, Tuple, List

import rpmfile

from obshell.log import logger


class Version(str):

    def __init__(self, bytes_or_buffer, encoding=None, errors=None):
        super(Version, self).__init__()

    @property
    def __cmp_value__(self):
        return [(int(_i), _s) for _i, _s in re.findall('(\d+)([^\._]*)', self.__str__())]

    def __eq__(self, value):
        if value is None:
            return False
        return self.__cmp_value__ == self.__class__(value).__cmp_value__

    def __gt__(self, value):
        if value is None:
            return True
        return self.__cmp_value__ > self.__class__(value).__cmp_value__

    def __ge__(self, value):
        if value is None:
            return True
        return self.__eq__(value) or self.__gt__(value)

    def __lt__(self, value):
        if value is None:
            return False
        return self.__cmp_value__ < self.__class__(value).__cmp_value__

    def __le__(self, value):
        if value is None:
            return False
        return self.__eq__(value) or self.__lt__(value)


class Release(Version):

    @property
    def __cmp_value__(self):
        m = re.search('(\d+)', self.__str__())
        return int(m.group(0)) if m else -1

    def simple(self):
        m = re.search('(\d+)', self.__str__())
        return m.group(0) if m else ""


class PackageInfo(object):

    def __init__(self, name, version, release, arch, md5, size):
        self.name = name
        self.set_version(version)
        self.set_release(release)
        self.arch = arch
        self.md5 = md5
        self.size = size

    def set_version(self, version):
        self.version = Version(str(version) if version else '')

    def set_release(self, release):
        self.release = Release(str(release) if release else '')

    @property
    def __cmp_value__(self):
        return [self.version, self.release]

    def __hash__(self):
        return hash(self.md5)

    def __eq__(self, value):
        if value is None:
            return False
        return self.md5 == value.md5

    def __ne__(self, value):
        return not self.__eq__(value)

    def __gt__(self, value):
        return value is None or self.__cmp_value__ > value.__cmp_value__
    
    def __ge__(self, value):
        return value is None or self.__eq__(value) or self.__cmp_value__ >= value.__cmp_value__

    def __lt__(self, value):
        if value is None:
            return False
        return self.__cmp_value__ < value.__cmp_value__

    def __le__(self, value):
        if value is None:
            return False
        return self.__eq__(value) or self.__cmp_value__ <= value.__cmp_value__


class ExtractFile(object):

    def __init__(self, path, context, mode, size):
        self.path = path
        self.context = context
        self.mode = mode
        self.size = size


def rpm_headers_list(rpm_headers):
    def ensure_list(param):
        if isinstance(param, (list, tuple)):
            return param
        return [param] if param is not None else []

    dirnames = ensure_list(rpm_headers.get("dirnames"))
    basenames = ensure_list(rpm_headers.get("basenames"))
    dirindexes = ensure_list(rpm_headers.get("dirindexes"))
    filelinktos = ensure_list(rpm_headers.get("filelinktos"))
    filemd5s = ensure_list(rpm_headers.get("filemd5s"))
    filemodes = ensure_list(rpm_headers.get("filemodes"))
    filesizes = ensure_list(rpm_headers.get("filesizes"))

    return dirnames, basenames, dirindexes, filelinktos, filemd5s, filemodes, filesizes


def load_rpm_pcakge(file_path) -> Tuple[List[ExtractFile], Dict[str, str]]:
    with rpmfile.open(file_path) as rpm:
        files = {}
        dirnames, basenames, dirindexes, filelinktos, filemd5s, filemodes, filesizes = rpm_headers_list(rpm.headers)
        format_str = lambda s: s.decode(errors='replace') if isinstance(s, bytes) else s

        for i in range(len(basenames)):
            if not filemd5s[i] and not filelinktos[i]:
                continue
            dir_path = format_str(dirnames[dirindexes[i]])
            if not dir_path.startswith('./'):
                dir_path = '.%s' % dir_path
            file_name = format_str(basenames[i])
            path = os.path.join(dir_path, file_name)
            files[path] = i
        

        need_extra_files = []
        need_links_files = {}
        for src_path in files:
            idx = files[src_path]
            if filemd5s[idx]:
                logger.debug("read file: %s" % src_path)
                need_extra_files.append(ExtractFile(
                    path=src_path,
                    context=rpm.extractfile(src_path).read(),
                    mode=filemodes[idx] & 0x1ff,
                    size=filesizes[idx]
                ))
            elif filelinktos[idx]:
                need_links_files[src_path] = format_str(filelinktos[idx])
            else:
                raise Exception('%s is directory' % src_path)
            
    need_extra_files = sorted(need_extra_files, key=lambda f: f.size, reverse=True)
    return need_extra_files, need_links_files

