# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import datetime
import pymisp
import unittest
from feed_manager import storage
from feed_manager import generator

from typing import Dict
from typing import List


UTC_NOW = datetime.datetime.utcnow()
UTC_TOMORROW = UTC_NOW + datetime.timedelta(days=1)
TEST_MD5_1 = "a" * 32
TEST_MD5_2 = "b" * 32


class InMemoryStorageLayer(storage.AbstractWriter):
    """In-Memory storage layer used for tests."""

    def __init__(self) -> None:
        """Constructor."""
        super().__init__()
        self.manifest = {}
        self.events = {}
        self.hashes = []

    def load_manifest(self) -> Dict:
        """Implement interface."""
        if not self.manifest:
            raise FileNotFoundError
        return self.manifest

    def load_event(self, event_uuid: str) -> Dict:
        """Implement interface."""
        try:
            return self.events[event_uuid]
        except KeyError:
            raise FileNotFoundError

    def load_hashes(self) -> List[List[str]]:
        """Implement interface."""
        return self.hashes

    def save_event(self, event_uuid: str, event_feed: Dict) -> None:
        """Implement interface."""
        self.events[event_uuid] = event_feed

    def save_manifest(self, manifest: Dict) -> None:
        """Implement interface."""
        self.manifest = manifest

    def save_hashes(self, attribute_hashes: List[List[str]]) -> None:
        """Implement interface."""
        self.hashes = attribute_hashes


class TestGenerator(unittest.TestCase):
    """Class to test the generator module."""

    def test__attributes__two_days(self):
        """Test adding two attributes in two different days."""
        storage_layer = InMemoryStorageLayer()
        feed_generator = generator.DailyFeedGenerator(storage_layer)
        feed_generator.add_attribute("md5", "a" * 32)
        feed_generator.flush()
        feed_generator.set_clock(UTC_TOMORROW)
        feed_generator.add_attribute("md5", "b" * 32)
        feed_generator.flush()
        self.assertEqual(len(storage_layer.manifest.keys()), 2)
        self.assertEqual(len(storage_layer.events), 2)
        self.assertEqual(len(storage_layer.hashes), 2)

    def test_attributes__flush_twice(self):
        """Test adding two attributes in one day and flushing twice."""
        storage_layer = InMemoryStorageLayer()
        feed_generator = generator.DailyFeedGenerator(storage_layer)
        feed_generator.add_attribute("md5", "a" * 32)
        feed_generator.flush()
        feed_generator.add_attribute("md5", "b" * 32)
        feed_generator.flush()
        self.assertEqual(len(storage_layer.manifest.keys()), 1)
        self.assertEqual(len(storage_layer.events), 1)
        self.assertEqual(len(storage_layer.hashes), 2)

    def test_attributes__flush_once(self):
        """Test adding two attributes in one day and flushing once."""
        storage_layer = InMemoryStorageLayer()
        feed_generator = generator.DailyFeedGenerator(storage_layer)
        feed_generator.add_attribute("md5", "a" * 32)
        feed_generator.add_attribute("md5", "b" * 32)
        feed_generator.flush()
        self.assertEqual(len(storage_layer.manifest.keys()), 1)
        self.assertEqual(len(storage_layer.events), 1)
        self.assertEqual(len(storage_layer.hashes), 2)

    def test_attributes__flush_once__miss(self):
        """Test adding two attributes in one day and flushing twice but once too late."""
        storage_layer = InMemoryStorageLayer()
        feed_generator = generator.DailyFeedGenerator(storage_layer)
        feed_generator.add_attribute("md5", "a" * 32)
        feed_generator.flush()
        feed_generator.add_attribute("md5", "b" * 32)
        self.assertEqual(len(storage_layer.manifest.keys()), 1)
        self.assertEqual(len(storage_layer.events), 1)
        self.assertEqual(len(storage_layer.hashes), 1)


class TestFeedUtils(unittest.TestCase):
    """Class to test the feed utils class."""

    def test_contains_attribute(self):
        """Test contain attribute."""
        misp_event = pymisp.MISPEvent()
        misp_event.add_attribute(type="md5", value="a" * 32)
        self.assertTrue(generator.FeedUtils.contains_attribute(misp_event, "md5", "a" * 32))
        self.assertFalse(generator.FeedUtils.contains_attribute(misp_event, "md5", "b" * 32))

    def test_contains_attribute_with_data(self):
        """Test contain attribute with data."""
        misp_event = pymisp.MISPEvent()
        misp_event.add_attribute(type="md5", value=TEST_MD5_1, data=b"data")
        self.assertFalse(generator.FeedUtils.contains_attribute(misp_event, "md5", TEST_MD5_1))
        self.assertFalse(generator.FeedUtils.contains_attribute(misp_event, "md5", TEST_MD5_2))
        self.assertTrue(
            generator.FeedUtils.contains_attribute(misp_event, "md5", TEST_MD5_1, data=b"data")
        )
        self.assertFalse(
            generator.FeedUtils.contains_attribute(
                misp_event, "md5", TEST_MD5_1, data=b"datadata"
            )
        )


if __name__ == "__main__":
    unittest.main()
