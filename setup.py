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

from setuptools import setup, find_packages

setup(
    name='obshell',
    version='0.0.2',
    packages=find_packages(),
    description='OBShell SDK is a powerful and easy-to-use Python library that provides developers with simple method calls to interact with the OBShell. OBShell SDK allows for quick integration, enabling developers to efficiently implement features and focus on creating value in their applications.',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    author='OceanBase',
    author_email='rongfeng.frf@oceanbase.com',
    url='https://github.com/oceanbase/obshell-sdk-python',
    license='Apache-2.0',
    install_requires=[
        'pycryptodome',
        'requests',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
    ],
    python_requires='>=3.6',
)
