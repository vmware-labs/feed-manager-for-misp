# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import abc
import collections
import datetime
import json
import logging
import os
import requests

from types import TracebackType
from typing import Any
from typing import Dict
from typing import Generator
from typing import Iterator
from typing import List
from typing import Optional
from typing import Type
from typing import TypeVar


class ObjectFactory:
    """Factory to decode complex objects from misp."""

    TELEMETRY_OBJECT_NAMES = frozenset(["atp-report", "sandbox-report"])

    def __init__(self, event_data: Dict):
        """Constructor."""
        self._uuid_to_object = {x["uuid"]: x for x in event_data["Event"]["Object"]}
        self._reference_uuid_to_uuids = collections.defaultdict(set)
        for uuid, obj in self._uuid_to_object.items():
            if "ObjectReference" in obj:
                references = {x["referenced_uuid"] for x in obj["ObjectReference"]}
                for reference in references:
                    self._reference_uuid_to_uuids[reference].add(uuid)

    def _get_referencing_objects(
        self,
        source_object: Dict,
        referencing_object_name: str,
    ) -> List[Dict]:
        """Get all the objects with a given name referencing the source object."""
        ret = []
        for referencing_uuid in self._reference_uuid_to_uuids[source_object["uuid"]]:
            referencing_object = self._uuid_to_object[referencing_uuid]
            if referencing_object["name"] == referencing_object_name:
                ret.append(referencing_object)
        return ret

    def parse_sandbox_report(self, file_object: Dict) -> Dict:
        """Parse the sandbox report."""
        ret = {
            "analysis.activities": [],
            "task.portal_url": [],
            "task.score": [],
        }
        sandbox_report = None
        for object_name in self.TELEMETRY_OBJECT_NAMES:
            try:
                sandbox_report = self._get_referencing_objects(file_object, object_name)[0]
                break
            except IndexError:
                pass
        if not sandbox_report:
            return ret
        for attr in sandbox_report["Attribute"]:
            if attr["object_relation"] == "permalink":
                ret["task.portal_url"] = attr["value"]
            elif attr["object_relation"] == "score":
                ret["task.score"] = attr["value"]
        ret["analysis.activities"] = [
            attribute["value"]
            for sig_hit in self._get_referencing_objects(sandbox_report, "sb-signature")
            for attribute in sig_hit["Attribute"]
        ]
        return ret

    @classmethod
    def parse_techniques(cls, tags) -> List[str]:
        """Parse the MITRE techniques included."""
        ret = []
        for object_tag in tags:
            tag_name, tag_value = object_tag.split("=")
            tag_value = tag_value.strip('"')
            if tag_name == "misp-galaxy:mitre-attack-pattern":
                technique, technique_id = tag_value.split(" - ")
                ret.append(f"{technique_id}: {technique}")
        return ret

    @classmethod
    def parse_file_object(cls, file_object) -> Dict[str, Optional[str]]:
        """Parse the file object."""
        ret = {
            "file.md5": None,
            "file.sha1": None,
            "file.sha256": None,
            "file.name": None,
        }
        for attr in file_object["Attribute"]:
            if attr["type"] == "filename":
                ret["file.name"] = attr["value"]
            elif attr["type"] == "sha1":
                ret["file.sha1"] = attr["value"]
            elif attr["type"] == "md5":
                ret["file.md5"] = attr["value"]
            elif attr["type"] == "sha256":
                ret["file.sha256"] = attr["value"]
        return ret


class FeedParserException(Exception):
    """Generic exception."""


class EmptyFeedException(FeedParserException):
    """Exception raised when the feed is empty."""


class FeedParser(abc.ABC):
    """Abstract class providing utility methods to all the parsers."""

    DEFAULT_FMT = "%Y-%m-%d %H:%M:%S"

    FILE_INDICATOR_TYPES = frozenset(
        [
            "md5",
            "sha1",
            "sha256",
        ]
    )

    NETWORK_INDICATOR_TYPES = frozenset(
        [
            "domain",
            "ip",
            "url",
        ]
    )

    FILE_OBJECT_TYPE = "file"

    NETWORK_OBJECT_TYPE = "network-profile"

    def __init__(self, event_data: Dict[str, Any]):
        """Constructor."""
        self._event_data = event_data
        self._uuid_to_object = {x["uuid"]: x for x in event_data["Event"]["Object"]}
        self._name_to_uuids = collections.defaultdict(list)
        for uuid, obj in self._uuid_to_object.items():
            self._name_to_uuids[obj["name"]].append(uuid)
        self._object_factory = ObjectFactory(event_data)

    @classmethod
    def _timestamp_to_date_str(cls, timestamp: float, fmt: str = None) -> str:
        """Convert a timestamp into a date string."""
        date_object = datetime.datetime.fromtimestamp(int(timestamp))
        return date_object.strftime(fmt or cls.DEFAULT_FMT)

    @classmethod
    def _get_tags_from_object(cls, object_data: Dict[str, Any]) -> List[str]:
        """Return the tags assigned to an object."""
        tags = set([])
        for attribute in object_data["Attribute"]:
            tags.update([x["name"] for x in attribute.get("Tag", [])])
        return sorted(tags)

    @classmethod
    def get_tags_from_event(cls, event_data: Dict[str, Any]) -> List[str]:
        """Get all the tags assigned to an event."""
        return sorted(set(x["name"] for x in event_data["Event"].get("Tag", [])))

    @abc.abstractmethod
    def __iter__(self) -> Iterator[Dict[str, Any]]:
        """Iterate."""

    def __enter__(self) -> Iterator[Dict[str, Any]]:
        """Return the iterator."""
        return iter(self)

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Exit the context."""


BaseFeedParserSubType = TypeVar("BaseFeedParserSubType", bound=FeedParser)


class IndicatorEventFeedParser(FeedParser):
    """Parser able to read feeds made of indicators."""

    def _process_object(self, uuid: str) -> Generator[Dict[str, Any], None, None]:
        """Parse an object and return the item representation."""
        object_data = self._uuid_to_object[uuid]
        object_tags = self._get_tags_from_object(object_data)
        for attribute in object_data["Attribute"]:
            if attribute["type"] in self.FILE_INDICATOR_TYPES | self.NETWORK_INDICATOR_TYPES:
                timestamp = self._timestamp_to_date_str(self._event_data["Event"]["timestamp"])
                yield {
                    "tags": object_tags,
                    "timestamp": timestamp,
                    "event_uuid": self._event_data["Event"]["uuid"],
                    "object_uuid": uuid,
                    "attribute_uuid": attribute["uuid"],
                    "attribute_type": attribute["type"],
                    "attribute_value": attribute["value"],
                }

    def __iter__(self) -> Generator[Dict[str, Any], None, None]:
        """Implement interface."""
        for obj in self._uuid_to_object.values():
            if obj["name"] in frozenset([self.FILE_OBJECT_TYPE, self.NETWORK_OBJECT_TYPE]):
                yield from self._process_object(obj["uuid"])


class TelemetryEventFeedParser(FeedParser):
    """Parser able to read feeds made of telemetry items."""

    def _process_object(self, uuid: str) -> Generator[Dict[str, Any], None, None]:
        """Parse an object provided its uuids."""
        object_data = self._uuid_to_object[uuid]
        object_tags = self._get_tags_from_object(object_data)
        yield {
            "tags": object_tags,
            "techniques": self._object_factory.parse_techniques(object_tags),
            **self._object_factory.parse_sandbox_report(object_data),
            **self._object_factory.parse_file_object(object_data),
        }

    def __iter__(self) -> Generator[Dict[str, Any], None, None]:
        """Implement interface."""
        for name, uuids in self._name_to_uuids.items():
            if name == self.FILE_OBJECT_TYPE:
                for uuid in uuids:
                    yield from self._process_object(uuid)


class AbstractFeedConsumer(abc.ABC):
    """Abstract implementation of a consumer."""

    @abc.abstractmethod
    def load_manifest(self) -> Dict:
        """Return the manifest as a dictionary."""

    @abc.abstractmethod
    def load_event(self, event_uuid) -> Dict:
        """Load the event as a dictionary."""

    @classmethod
    def _infer_parser_class(cls, event_data: Dict) -> Type[BaseFeedParserSubType]:
        """Return the parser class able to read the feed."""
        try:
            objects_data = event_data["Event"]["Object"]
        except KeyError:
            raise EmptyFeedException
        for object_data in objects_data:
            if object_data["name"] in ObjectFactory.TELEMETRY_OBJECT_NAMES:
                return TelemetryEventFeedParser
        return IndicatorEventFeedParser

    def _get_event_uuids_since(self, since_timestamp: float = None) -> List[str]:
        """Read the manifest and return the event uuids matching the filter."""
        event_uuids = []
        for event_uuid, event_data in self.load_manifest().items():
            if not since_timestamp or event_data["timestamp"] > since_timestamp:
                event_uuids.append(event_uuid)
        return event_uuids

    def _get_events_since(self, date_object: datetime.datetime) -> List[Dict]:
        """Return list of event data objects."""
        event_uuids = self._get_event_uuids_since(date_object.timestamp())
        return [self.load_event(x) for x in event_uuids]

    @classmethod
    def _get_tag_galaxy(cls, tag_name: str) -> Optional[str]:
        """Get the galaxy if the tag is a MISP galaxy cluster."""
        try:
            category = tag_name.split("=")[0]
            tag_type, tag_galaxy = category.split(":")
            return tag_galaxy if tag_type == "misp-galaxy" else None
        except (ValueError, IndexError):
            return None

    @classmethod
    def _filter_indicator(
        cls,
        indicator: Dict[str, Any],
        attribute_type: Optional[str] = None,
        galaxy_name: Optional[str] = None,
    ) -> bool:
        """Return false if the indicator shall NOT be included."""
        if attribute_type and indicator["attribute_type"] != attribute_type:
            return False
        if galaxy_name and all(cls._get_tag_galaxy(x) != galaxy_name for x in indicator["tags"]):
            return False
        return True

    def get_items_since(
        self,
        date_object: datetime.datetime,
        attribute_type: Optional[str] = None,
        galaxy_name: Optional[str] = None,
    ) -> List[Dict]:
        """Return the items contained in the feed."""
        ret = []
        for event_data in self._get_events_since(date_object):
            try:
                parser_class = self._infer_parser_class(event_data)
                with parser_class(event_data) as parser:
                    for indicator in parser:
                        if self._filter_indicator(indicator, attribute_type, galaxy_name):
                            ret.append(indicator)
            except EmptyFeedException:
                self._logger.warning("The feed '%s' is empty", event_data["Event"]["info"])
        return ret

    def __init__(self):
        """Constructor."""
        self._logger = logging.getLogger(__name__)


class LocalFeedConsumer(AbstractFeedConsumer):
    """Consumer using a local directory."""

    def load_manifest(self) -> Dict:
        """Implement interface."""
        with open(os.path.join(self._input_dir, "manifest.json"), "r") as f:
            return json.load(f)

    def load_event(self, event_uuid: str) -> Dict:
        """Implement interface."""
        with open(os.path.join(self._input_dir, f"{event_uuid}.json"), "r") as f:
            return json.load(f)

    def __init__(self, input_dir: str):
        """Constructor."""
        super(LocalFeedConsumer, self).__init__()
        self._input_dir = input_dir


class RemoteFeedConsumer(AbstractFeedConsumer):
    """Consumer using a remote (HTTP) source."""

    DEFAULT_TIMEOUT = 60

    def load_manifest(self) -> Dict:
        """Implement interface."""
        ret = requests.get(f"{self._base_url}/manifest.json", timeout=self.DEFAULT_TIMEOUT)
        return ret.json()

    def load_event(self, event_uuid: str) -> Dict:
        """Implement interface."""
        ret = requests.get(f"{self._base_url}/{event_uuid}.json", timeout=self.DEFAULT_TIMEOUT)
        return ret.json()

    def __init__(self, base_url: str):
        """Constructor."""
        super(RemoteFeedConsumer, self).__init__()
        self._base_url = base_url.rstrip("/")
