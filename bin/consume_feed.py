#!/usr/bin/env python3
# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import argparse
import collections
import datetime
import json
import sys

from feed_manager import consumer

from typing import Dict
from typing import List
from typing import Tuple


def get_date_range(start_date: datetime.date, end_date: datetime.date) -> List[datetime.date]:
    """Get a range of date objects with no gaps."""
    ranges = {
        start_date + datetime.timedelta(days=x) for x in range((end_date - start_date).days)
    }
    ranges.add(start_date)
    ranges.add(end_date)
    return sorted(ranges)


def compute_statistics(indicators: List[Dict]) -> Dict[datetime.date, Tuple[int, Dict]]:
    """Compute statistics from a list of indicators."""
    ret = {}
    attribute_uuid_to_tags = collections.defaultdict(set)
    date_to_attribute_uuids = collections.defaultdict(list)
    for indicator in indicators:
        attribute_uuid_to_tags[indicator["attribute_uuid"]].update(indicator["tags"])
        date_object = datetime.datetime.strptime(
            indicator["timestamp"], consumer.FeedParser.DEFAULT_FMT
        ).date()
        date_to_attribute_uuids[date_object].append(indicator["attribute_uuid"])
    try:
        min_date = min(date_to_attribute_uuids)
        max_date = max(date_to_attribute_uuids)
    except ValueError:
        return ret
    ret = {}
    for date_object in get_date_range(min_date, max_date):
        tag_to_count = collections.Counter()
        try:
            nb_attributes = len(date_to_attribute_uuids[date_object])
            for attribute_uuid in date_to_attribute_uuids[date_object]:
                for tag in attribute_uuid_to_tags[attribute_uuid]:
                    tag_to_count[tag] += 1
        except KeyError:
            nb_attributes = 0
        ret[date_object] = (nb_attributes, tag_to_count)
    return ret


def main():
    """Simple script to consume a daily feed."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input-location",
        dest="input_location",
        type=str,
        default=None,
        required=True,
        help="location of the feed",
    )
    parser.add_argument(
        "-t",
        "--attribute-type",
        dest="attribute_type",
        type=str,
        default=None,
        help="the attribute type (e.g., sha1)",
    )
    parser.add_argument(
        "-g",
        "--galaxy-name",
        dest="galaxy_name",
        type=str,
        default=None,
        help="filter by MISP galaxy (e.g., malpedia)",
    )
    parser.add_argument(
        "-d",
        "--day-delta",
        dest="day_delta",
        type=int,
        default=7,
        help="the look back in terms of days",
    )
    args = parser.parse_args()

    since_date_object = datetime.datetime.utcnow() - datetime.timedelta(days=args.day_delta)
    if args.input_location.startswith("http"):
        consumer_class = consumer.RemoteFeedConsumer
    else:
        consumer_class = consumer.LocalFeedConsumer
    feed_consumer = consumer_class(args.input_location)
    indicators = feed_consumer.get_items_since(
        date_object=since_date_object,
        attribute_type=args.attribute_type,
        galaxy_name=args.galaxy_name,
    )

    print(f"Fetching items since {since_date_object}")
    for indicator in indicators:
        print(json.dumps(indicator, indent=True))

    print("Computing statistics")
    try:
        statistics = compute_statistics(indicators)
    except KeyError:
        print("Not supported on telemetry feeds")
    else:
        for date_object, (nb_attributes, tag_to_count) in statistics.items():
            print(f"{date_object} - indicators: {nb_attributes}")
            for tag, count in sorted(tag_to_count.items()):
                print(f"\t{tag}: {count}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
