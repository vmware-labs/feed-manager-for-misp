# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import abc
import datetime
import hashlib
import json
import logging
import os

from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

import feed_manager
from feed_manager import translator

try:
    import pymisp
except ImportError as ie:
    pymisp = None
    feed_manager.print_dependency_error_and_raise(ie)


class FeedProperties:
    """Class to represent the properties of a feed."""

    DEFAULT_ORG_NAME = "Organization"
    DEFAULT_ORG_UUID = "a6b0e426-8c54-4136-beb6-3c2bafac7c4b"
    DEFAULT_FEED_NAME = "Feed"

    @classmethod
    def create_organization(
        cls,
        name: str = DEFAULT_ORG_NAME,
        uuid: str = DEFAULT_ORG_UUID,
    ) -> pymisp.MISPOrganisation:
        organization = pymisp.MISPOrganisation()
        organization.from_dict(
            name=name,
            uuid=uuid,
        )
        return organization

    def __init__(
        self,
        analysis: pymisp.Analysis = pymisp.Analysis.initial,
        threat_level_id: pymisp.ThreatLevel = pymisp.ThreatLevel.low,
        title: str = DEFAULT_FEED_NAME,
        published: bool = False,
        tags: Optional[List[Union[pymisp.MISPTag, str]]] = None,
        organization: Optional[pymisp.MISPOrganisation] = None,
    ):
        if not organization:
            organization = self.create_organization()
        if not tags:
            tags = []
        self.organization = organization
        self.analysis = analysis
        self.tags = [translator.TagUtils.validate_tag(x) for x in tags]
        self.threat_level_id = threat_level_id
        self.published = published
        self.title = title


class FeedGenerationException(Exception):
    """Generic exception."""


class FeedEventNotFound(FeedGenerationException):
    """Exception raised when the feed has not the required event."""


class AbstractFeedGenerator(abc.ABC):
    """Abstract class for every feed generators."""

    def __init__(self, output_dir):
        """Constructor."""
        self._logger = logging.getLogger(__name__)
        self._output_dir = output_dir
        self._attribute_hashes = []
        self._manifest = {}

    @staticmethod
    def attribute_equals(attr1: pymisp.MISPAttribute, attr2: pymisp.MISPAttribute) -> bool:
        """Return whether two attributes are the same."""
        return (
            attr1.type == attr2.type and attr1.value == attr2.value and attr1.data == attr2.data
        )

    @staticmethod
    def tag_equals(tag1: pymisp.MISPTag, tag2: pymisp.MISPTag) -> bool:
        """Return whether two tags are the same."""
        return tag1.name == tag2.name

    @classmethod
    def object_equals(cls, obj1: pymisp.MISPObject, obj2: pymisp.MISPObject) -> bool:
        """Return whether two objects are the same."""
        obj1_attributes = sorted(obj1.attributes, key=lambda x: x.type)
        obj2_attributes = sorted(obj2.attributes, key=lambda x: x.type)
        if len(obj1_attributes) != len(obj2_attributes):
            return False
        return all(
            cls.attribute_equals(attr1, attr2)
            for attr1, attr2 in zip(obj1_attributes, obj2_attributes)
        )

    @classmethod
    def contains_attribute(
        cls,
        misp_event: pymisp.MISPEvent,
        attr_type: str,
        attr_value: str,
        **attr_data,
    ) -> bool:
        """Return whether the misp event contains a specific attribute."""
        fake_attribute = pymisp.MISPAttribute()
        fake_attribute.from_dict(
            type=attr_type,
            value=attr_value,
            data=attr_data,
        )
        return any(cls.attribute_equals(fake_attribute, attr) for attr in misp_event.attributes)

    @classmethod
    def contains_object(
        cls, misp_event: pymisp.MISPEvent, misp_object: pymisp.MISPObject
    ) -> bool:
        """Return whether the misp event contains a specific object."""
        return any(cls.object_equals(obj, misp_object) for obj in misp_event.objects)

    @classmethod
    def contains_tag(cls, misp_event: pymisp.MISPEvent, misp_tag: pymisp.MISPTag) -> bool:
        return any(cls.tag_equals(tag, misp_tag) for tag in misp_event.tags)

    @abc.abstractmethod
    def add_object_to_event(self, misp_object: pymisp.MISPObject) -> bool:
        """Add object to the current event."""

    @abc.abstractmethod
    def add_tag_to_event(self, misp_tag: pymisp.MISPTag) -> bool:
        """Add tag to the current event."""

    @abc.abstractmethod
    def add_attribute_to_event(self, attr_type: str, attr_value: str, **attr_data) -> bool:
        """Add an attribute to the current event."""

    @abc.abstractmethod
    def flush_event(self, event: Optional[pymisp.MISPEvent] = None) -> None:
        """Flush the current event (if not specified)."""

    def _load_event(self, event_uuid: str) -> pymisp.MISPEvent:
        """Load an event give its uuid."""
        with open(os.path.join(self._output_dir, f"{event_uuid}.json"), "r") as f:
            event_dict = json.load(f)["Event"]
            event = pymisp.MISPEvent()
            event.from_dict(**event_dict)
            return event

    def _save_manifest(self) -> None:
        """Save the manifest to disk."""
        with open(os.path.join(self._output_dir, "manifest.json"), "w") as manifest_file:
            json.dump(self._manifest, manifest_file, indent=True)
        self._logger.debug("Manifest saved")

    def _load_manifest(self) -> Dict[str, Dict]:
        """Load the manifest."""
        manifest_path = os.path.join(self._output_dir, "manifest.json")
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
        return manifest

    def _add_hash(self, event: pymisp.MISPEvent, attr_type: str, attr_value: str) -> None:
        """Take the attribute properties and add a hash."""
        _ = attr_type
        for frag in str(attr_value).split("|"):
            frag_hash = hashlib.md5(str(frag).encode("utf-8"), usedforsecurity=False).hexdigest()
            self._attribute_hashes.append([frag_hash, event.get("uuid")])

    def _save_hashes(self) -> None:
        """Save the collected hashes to disk."""
        with open(os.path.join(self._output_dir, "hashes.csv"), "a") as hash_file:
            for element in self._attribute_hashes:
                hash_file.write(f"{element[0]},{element[1]}\n")
        self._logger.debug("Hashes saved")
        self._attribute_hashes.clear()


class PeriodicFeedGenerator(AbstractFeedGenerator, abc.ABC):
    """A periodic feed generator that needs to be specialized further."""

    @classmethod
    @abc.abstractmethod
    def get_bucket(cls, date_obj: datetime.datetime) -> str:
        """Return the periodic bucket given the provided date object."""

    @classmethod
    @abc.abstractmethod
    def parse_bucket(cls, date_str: str) -> datetime.datetime:
        """Given a bucket return the date time object."""

    def get_current_bucket(self) -> str:
        """Get the current bucket (truncated datetime object)."""
        return self.get_bucket(self._event_date_callback())

    def __init__(
        self,
        output_dir: str,
        feed_properties: Optional[FeedProperties] = None,
        date_override: Optional[datetime.datetime] = None,
    ):
        """Constructor."""
        super(PeriodicFeedGenerator, self).__init__(output_dir)
        self._feed_properties = feed_properties or FeedProperties()
        # Set up the callback used to know the current date at which we are inserting items
        if date_override:
            self._event_date_callback = lambda: date_override
        else:
            self._event_date_callback = lambda: datetime.datetime.utcnow()

        # Load the manifest but create it in case it is empty
        try:
            self._manifest = self._load_manifest()
        except FileNotFoundError:
            self._logger.debug("Manifest not found, generating a new one")
            self._manifest = {}
            new_event = self._create_event(self.get_current_bucket())
            # flush new event for the first time and manifest
            self.flush_event(event=new_event)
            self._manifest.update(new_event.manifest)
            self._save_manifest()

        # Load the current event but load it if the existing manifest does not have it
        if date_override:
            self._logger.debug("Creating a feed with an overriden date: %s", date_override)
            try:
                event_uuid, event_date_str = self._get_event_metadata(date_override)
            except FeedEventNotFound:
                self._logger.debug("The overridden date does not have an event. Creating it...")
                new_event = self._create_event(self.get_current_bucket())
                self.flush_event(event=new_event)
                self._manifest.update(new_event.manifest)
                self._save_manifest()
                event_uuid, event_date_str = self._get_event_metadata(date_override)
        else:
            event_uuid, event_date_str = self._get_last_event_metadata()
        self._current_event_bucket = self.get_bucket(self.parse_bucket(event_date_str))
        self._current_event = self._load_event(event_uuid)

    def add_object_to_event(self, misp_object: pymisp.MISPObject) -> bool:
        """Implement interface."""
        self._update_event_bucket()
        if self.contains_object(self._current_event, misp_object):
            return False
        self._current_event.add_object(misp_object)
        for attribute in misp_object.attributes:
            self._add_hash(self._current_event, attribute.type, attribute.value)
        return True

    def add_attribute_to_event(self, attr_type: str, attr_value: str, **attr_data) -> bool:
        """Implement interface."""
        self._update_event_bucket()
        if self.contains_attribute(self._current_event, attr_type, attr_value, **attr_data):
            return False
        self._current_event.add_attribute(attr_type, attr_value, **attr_data)
        self._add_hash(self._current_event, attr_type, attr_value)
        return True

    def add_tag_to_event(self, misp_tag: pymisp.MISPTag) -> bool:
        """Implement interface."""
        self._update_event_bucket()
        if self.contains_tag(self._current_event, misp_tag):
            return False
        self._current_event.add_tag(misp_tag)
        return True

    def flush_event(self, event: Optional[pymisp.MISPEvent] = None) -> None:
        """Implement interface."""
        if not event:
            event = self._current_event
        with open(os.path.join(self._output_dir, event.get("uuid") + ".json"), "w") as event_file:
            json.dump(event.to_feed(), event_file, indent=True)
        self._save_hashes()

    def _update_event_bucket(self) -> None:
        """Update the current bucket if needed."""
        event_bucket = self.get_current_bucket()
        if self._current_event_bucket != event_bucket:
            self._logger.debug(
                "New event bucket required (new=%s, old=%s)",
                event_bucket,
                self._current_event_bucket,
            )
            # flush previous event
            self.flush_event()
            # create new event
            self._current_event_bucket = event_bucket
            self._current_event = self._create_event(event_bucket)
            # flush new event for the first time and manifest
            self.flush_event()
            self._manifest.update(self._current_event.manifest)
            self._save_manifest()

    def _get_last_event_metadata(self) -> Tuple[str, str]:
        """Get the metadata related to the latest event."""
        dated_events = []
        for event_uuid, event_json in self._manifest.items():
            dated_events.append(
                (
                    event_json["date"],
                    event_uuid,
                    event_json["info"],
                )
            )
        # Sort by date then by event name
        dated_events.sort(key=lambda k: (k[0], k[2], k[1]), reverse=True)
        return dated_events[0][1], dated_events[0][0]

    def _get_event_metadata(
        self,
        date_obj: datetime.datetime,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Get the metadata related to the event matching the date provided."""
        date_str = self.get_bucket(date_obj)
        for event_uuid, event_json in self._manifest.items():
            if event_json["date"] == date_str:
                return event_uuid, event_json["date"]
        raise FeedEventNotFound

    def _create_event(self, event_bucket: str) -> pymisp.MISPEvent:
        """Create an even in the given bucket."""
        event = pymisp.MISPEvent()
        event.from_dict(
            **{
                "id": str(len(self._manifest) + 1),
                "info": f"{self._feed_properties.title} ({event_bucket})",
                "date": event_bucket,
                "analysis": self._feed_properties.analysis.value,
                "threat_level_id": self._feed_properties.threat_level_id.value,
                "published": self._feed_properties.published,
                "timestamp": int(self.parse_bucket(event_bucket).timestamp()),
            }
        )
        for tag in self._feed_properties.tags:
            event.add_tag(tag)
        event.Orgc = self._feed_properties.organization
        return event


class DailyFeedGenerator(PeriodicFeedGenerator):
    """A feed generator that creates a different event every day."""

    BUCKET_FMT = "%Y-%m-%d"

    @classmethod
    def parse_bucket(cls, date_str: str) -> datetime.datetime:
        """Implement interface"""
        return datetime.datetime.strptime(date_str, cls.BUCKET_FMT)

    @classmethod
    def get_bucket(cls, date_obj: datetime.datetime) -> str:
        """Implement interface."""
        return date_obj.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        ).strftime(cls.BUCKET_FMT)
