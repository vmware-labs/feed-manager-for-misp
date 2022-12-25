# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import re

from typing import Optional


HEX_RE = re.compile(r"^[a-fA-F0-9]*$")


def get_hash_type(hash_value: str) -> Optional[str]:
    """Get the hash type."""
    if len(hash_value) == 32:
        return "md5" if HEX_RE.match(hash_value) else None
    elif len(hash_value) == 40:
        return "sha1" if HEX_RE.match(hash_value) else None
    elif len(hash_value) == 64:
        return "sha256" if HEX_RE.match(hash_value) else None
    else:
        return None


def print_dependency_error_and_raise(exception: Exception):
    """Print the error of the missing dependency and re-raise."""
    print("Only 'consumer.py' and 'consume_feed.py' do not require the 'misp' extra dependency")
    raise exception
