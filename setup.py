# SPDX-License-Identifier: GPL-3.0-or-later
#This is ZHESP2(Zero's Hash Encryption Secure Protocol v2)
# Copyright (C) 2025  Gage Singleton <zeroday@mail.i2p>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
from setuptools import setup, find_packages

setup(
    name="zhesp2",
    version="2.5.0",
    author="Zero",
    description="Z-HESP2 — Zero’s Hash Encryption Secure Protocol",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.7",
    install_requires=[
        "pycryptodome>=3.19.0",
        "argon2-cffi>=21.3.0",
        "cryptography>=41.0.0",
    ],
    entry_points={
        "console_scripts": [
            "zhesp2=zhesp2.__main__:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    ],
)
