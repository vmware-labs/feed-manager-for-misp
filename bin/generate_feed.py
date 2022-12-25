#!/usr/bin/env python3
# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import argparse
import os
import pathlib
import sys

from typing import Any
from typing import Dict
from typing import List

import feed_manager
from feed_manager import translator
from feed_manager import generator

try:
    import pymisp
except ImportError as ie:
    pymisp = None
    feed_manager.print_dependency_error_and_raise(ie)


INDICATOR_MD5 = "a" * 32

INDICATOR_SHA1 = "b" * 40

INDICATOR_SHA256 = "c" * 64

INDICATOR_TAGS = [
    'misp-galaxy:malpedia="GootKit"',
    'misp-galaxy:threat-actor="Sofacy"',
]

TELEMETRY_ITEM = {
    "file.sha1": "a1f7670cd7da7e331db2d69f0855858985819873",
    "file.mime_type": "application/x-pe-app-32bit-i386",
    "analysis.label": "unclassified",
    "task.severity": "malicious",
    "file.llfile_type": "PeExeFile",
    "analysis.mitre_tactics": ["TA0005: Defense Evasion", "TA0007: Discovery"],
    "file.md5": "37840d4e937db0385b820d4019071540",
    "task.portal_url": (
        "https://user.lastline.com/portal#/analyst/task/"
        "30f48c17e9db002005baa7d440ca275a/overview"
    ),
    "file.magic": "Unknown",
    "task.uuid": "30f48c17e9db002005baa7d440ca275a",
    "source.origin": "API",
    "file.sha256": "492bfe8d2b1105ec4045f96913d38f98e30fe349ea50cc4aaa425ca289af2852",
    "customer.sector": "IT",
    "analysis.activities": [
        "Anomaly: AI detected possible malicious code reuse",
        "Evasion: Detecting the presence of AntiMalware Scan Interface (AMSI)",
        "Execution: Subject crash detected",
        "Signature: Potentially malicious application/program",
    ],
    "analysis.mitre_techniques": ["T1497: Virtualization/Sandbox Evasion"],
    "task.score": 70,
    "customer.region": "AMER",
    "utc_timestamp": 1663568636000,
    "file.size": 990720,
    "file.name": None,
    "research.tag.name": [],
    "research.tag.value": [],
}

SANDBOX_NAME = "Test Sandbox"


def from_telemetry_item_to_objects(item: Dict[str, Any]) -> List[pymisp.MISPObject]:
    """Convert a telemetry item into objects."""
    objects = []
    file_object = translator.IndicatorTranslator.to_file_object(
        file_md5=item["file.md5"],
        file_sha1=item["file.sha1"],
        file_sha256=item["file.sha256"],
        file_name=item.get("file.name"),
        mime_type=item.get("file.mime_type"),
        size=item.get("file.size"),
    )
    objects.append(file_object)
    sandbox_object = pymisp.MISPObject(name="sandbox-report")
    sandbox_object.add_attribute("score", item["task.score"])
    sandbox_object.add_attribute("saas-sandbox", SANDBOX_NAME)
    sandbox_object.add_attribute("permalink", item["task.portal_url"])
    sandbox_object.add_reference(
        referenced_uuid=file_object.uuid,
        relationship_type="report-of",
    )
    objects.append(sandbox_object)
    if item.get("analysis.activities"):
        sig_object = pymisp.MISPObject(name="sb-signature")
        for activity in item["analysis.activities"]:
            sig_object.add_attribute("signature", type="text", value=activity)
        sig_object.add_reference(
            referenced_uuid=sandbox_object.uuid,
            relationship_type="belongs-to",
        )
        objects.append(sig_object)
    return objects


def main():
    """Simple script to generate a daily feed."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        type=str,
        default="./tmp/",
        help="the local feed",
    )
    args = parser.parse_args()

    # Test the indicator feed
    indicators_path = os.path.join(args.output_dir, "indicators")
    pathlib.Path(indicators_path).mkdir(parents=True, exist_ok=True)
    misp_object = translator.IndicatorTranslator.to_file_object(
        file_md5=INDICATOR_MD5,
        file_sha1=INDICATOR_SHA1,
        file_sha256=INDICATOR_SHA256,
        tags=INDICATOR_TAGS,
    )
    feed_generator = generator.DailyFeedGenerator(
        output_dir=indicators_path,
        feed_properties=generator.FeedProperties(
            title="Test indicators feed",
        ),
    )
    feed_generator.add_object_to_event(misp_object)
    feed_generator.flush_event()
    print(f"Daily feed of indicators written to: {indicators_path}")

    # Test the telemetry feed
    telemetry_path = os.path.join(args.output_dir, "telemetry")
    pathlib.Path(telemetry_path).mkdir(parents=True, exist_ok=True)
    misp_objects = from_telemetry_item_to_objects(TELEMETRY_ITEM)
    feed_generator = generator.DailyFeedGenerator(
        output_dir=telemetry_path,
        feed_properties=generator.FeedProperties(
            title="Test telemetry feed",
        ),
    )
    for misp_object in misp_objects:
        feed_generator.add_object_to_event(misp_object)
    feed_generator.flush_event()
    print(f"Daily feed of telemetry objects written to: {telemetry_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
