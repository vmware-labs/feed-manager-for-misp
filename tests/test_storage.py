# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import ddt
import io
import unittest
from feed_manager import storage


@ddt.ddt
class TestStorage(unittest.TestCase):
    """Class to test the storage module."""

    @ddt.data(
        (io.TextIOWrapper(io.BytesIO(b"hash1,hash2"), encoding="utf-8"), [["hash1", "hash2"]]),
        (io.TextIOWrapper(io.BytesIO(b""), encoding="utf-8"), []),
        (io.TextIOWrapper(io.BytesIO(b" "), encoding="utf-8"), []),
        ([""], []),
        ([" "], []),
        (["hash1,hash2"], [["hash1", "hash2"]]),
        (["hash1,hash2", "hash3,hash4"], [["hash1", "hash2"], ["hash3", "hash4"]]),
    )
    def test_parse_csv(self, args):
        """Test parsing CSV files."""
        csv_data, expected_output = args
        output = storage.AbstractReader._parse_csv(csv_data)
        self.assertEqual(output, expected_output)


if __name__ == "__main__":
    unittest.main()
