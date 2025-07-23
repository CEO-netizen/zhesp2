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

# Argon2id default parameters
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 2
ARGON2_HASH_LENGTH = 32

# File path for integrity flag
INTEGRITY_FLAG_FILE = "~/.zhesp2_verified"

# File shredding parameters
SHREDDING_PASSES = 3

# Colorama color codes (to be used in CLI)
COLOR_INFO = "cyan"
COLOR_SUCCESS = "green"
COLOR_ERROR = "red"
