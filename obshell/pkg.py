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
from typing import Dict, Tuple, List

import rpmfile

from obshell.log import logger


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

