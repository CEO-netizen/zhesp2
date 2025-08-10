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
# Configuration constants and default parameters for ZHESP2

VERSION = 2

VERSIONS_INFO = {
    1: {
        "name": "ZH1",
        "description": "Initial release - AES-256-CBC encryption, PBKDF2 key derivation",
        "status": "deprecated"
    },
    2: {
        "name": "ZH2",
        "description": "Current stable release - Argon2id KDF, metadata support, base64 & hex output",
        "status": "stable"
    },
    # Add future versions here
}

# Security profiles configuration
SECURITY_PROFILES = {
    "fast": {
        "name": "Fast",
        "description": "Optimized for speed with reasonable security",
        "argon2_params": {
            "time_cost": 2,
            "memory_cost": 65536,  # 64MB
            "parallelism": 2,
            "hash_length": 32
        },
        "allowed_algorithms": ["AES-GCM"],
        "default_algorithm": "AES-GCM"
    },
    "secure": {
        "name": "Secure",
        "description": "Balanced security and performance (default)",
        "argon2_params": {
            "time_cost": 5,
            "memory_cost": 131072,  # 128MB
            "parallelism": 4,
            "hash_length": 32
        },
        "allowed_algorithms": ["AES-GCM", "XChaCha20-Poly1305"],
        "default_algorithm": "XChaCha20-Poly1305"
    },
    "paranoid": {
        "name": "Paranoid",
        "description": "Maximum security with higher computational cost",
        "argon2_params": {
            "time_cost": 10,
            "memory_cost": 262144,  # 256MB
            "parallelism": 8,
            "hash_length": 32
        },
        "allowed_algorithms": ["XChaCha20-Poly1305"],
        "default_algorithm": "XChaCha20-Poly1305"
    }
}

# Default security profile
DEFAULT_SECURITY_PROFILE = "secure"

# Algorithm identifiers for payload format
ALGORITHM_AES_GCM = 0x01
ALGORITHM_XCHACHA20_POLY1305 = 0x02

# Argon2id default parameters (legacy - now uses security profiles)
ARGON2_TIME_COST = 5
ARGON2_MEMORY_COST = 131072
ARGON2_PARALLELISM = 4
ARGON2_HASH_LENGTH = 32

# File path for integrity flag
INTEGRITY_FLAG_FILE = "~/.zhesp2_verified"

# File shredding parameters
SHREDDING_PASSES = 3

# Colorama color codes (to be used in CLI)
COLOR_INFO = "cyan"
COLOR_SUCCESS = "green"
COLOR_ERROR = "red"
