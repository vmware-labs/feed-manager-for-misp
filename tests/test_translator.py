# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import ddt
import unittest
from feed_manager import translator


@ddt.ddt
class TestModule(unittest.TestCase):
    """Class to test the module."""

    @ddt.data(
        ("test=value", None, "value"),
        ('misp-galaxy:malpedia="test"', None, "test"),
        ('misp-galaxy:malpedia="test"', "misp-galaxy:malpedia", "test"),
        ('misp-galaxy:malpedia="test"', "misp-galaxy:another", None),
        ('misp-galaxy:malpedia2="test2"', None, "test2"),
        (translator.TagUtils.create_tag('misp-galaxy:malpedia="test"'), None, "test"),
    )
    def test_get_cluster_tag_value(self, args):
        """Test 'get_cluster_tag_value'."""
        tag, category, expected_output = args
        output = translator.TagUtils.get_cluster_tag_value(tag, category)
        self.assertEqual(output, expected_output)

    @ddt.data(
        ('malpedia2="test2"', ("malpedia2", "test2")),
        ('misp-galaxy:malpedia="test"', ("misp-galaxy:malpedia", "test")),
        ('misp-galaxy:malpedia2="test2"', ("misp-galaxy:malpedia2", "test2")),
        (
            translator.TagUtils.create_tag('misp-galaxy:malpedia="test"'),
            ("misp-galaxy:malpedia", "test"),
        ),
    )
    def test_get_cluster_category_and_value(self, args):
        """Test 'get_cluster_category_and_value'."""
        tag, expected_output = args
        output = translator.TagUtils.get_cluster_category_and_value(tag)
        self.assertEqual(output, expected_output)

    @ddt.data(
        ('malpedia2="test2"', (None, None)),
        ('misp-galaxy:malpedia="test"', ("malpedia", "test")),
        ('misp-galaxy:malpedia2="test2"', ("malpedia2", "test2")),
        (translator.TagUtils.create_tag('misp-galaxy:malpedia="test"'), ("malpedia", "test")),
    )
    def test_get_cluster_galaxy_and_value(self, args):
        """Test 'get_cluster_galaxy_and_value'."""
        tag, expected_output = args
        output = translator.TagUtils.get_cluster_galaxy_and_value(tag)
        self.assertEqual(output, expected_output)


if __name__ == "__main__":
    unittest.main()
