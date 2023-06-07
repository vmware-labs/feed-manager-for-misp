# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import ddt
import unittest

from unittest.mock import MagicMock

from feed_manager import consumer


@ddt.ddt
class TestFeedConsumer(unittest.TestCase):
    """Class to test the FeedConsumer class."""

    FEED_MANIFEST = {
        "UUID2023_06_03_00": {"timestamp": 1685750400},
        "UUID2023_06_04_00": {"timestamp": 1685836800},
        "UUID2023_06_05_00": {"timestamp": 1685923200},
        "UUID2023_06_05_04": {"timestamp": 1685930400},
    }

    @ddt.data(
        (1686009600, 1686009600),  # Tue Jun 06 2023 00:00:00 GMT+0000
        (1686002400, 1685923200),  # Mon Jun 05 2023 00:00:00 GMT+0000
        (1686048389, 1686009600),  # Tue Jun 06 2023 00:00:00 GMT+0000
        (1686002399, 1685923200),  # Mon Jun 05 2023 00:00:00 GMT+0000
    )
    def test_round_timestamp_to_day(self, args):
        input_timestamp, expected_timestamp = args
        returned_timestamp = consumer.FeedConsumer._round_timestamp_to_day(input_timestamp)
        self.assertEqual(expected_timestamp, returned_timestamp)

    @ddt.data(
        (1685750400, ["UUID2023_06_03_00"]),
        (1685836824, ["UUID2023_06_04_00"]),
        (1685955600, ["UUID2023_06_05_00", "UUID2023_06_05_04"]),
    )
    def test__get_event_uuids_on(self, args):
        timestamp, expected_uuids = args
        c = consumer.FeedConsumer(None)
        c._storage_layer = MagicMock()
        c._storage_layer.load_manifest.return_value = self.FEED_MANIFEST
        returned_uuids = c._get_event_uuids_on(timestamp)
        self.assertEqual(returned_uuids, expected_uuids)


if __name__ == "__main__":
    unittest.main()
