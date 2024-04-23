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

import re


class Version(str):

    def __init__(self, bytes_or_buffer, encoding=None, errors=None):
        super(Version, self).__init__()
        self.__val__ = [(int(_i), _s) for _i, _s in re.findall('(\d+)([^\._]*)', self.__str__())]

    def __eq__(self, value):
        return value is not None and self.__val__ == self.__class__(value).__val__

    def __gt__(self, value):
        return value is None or self.__val__ > self.__class__(value).__val__

    def __ge__(self, value):
        return value is None or self.__eq__(value) or self.__gt__(value)

    def __lt__(self, value):
        return value is not None and self.__val__ < self.__class__(value).__val__

    def __le__(self, value):
        return self.__eq__(value) or self.__lt__(value)