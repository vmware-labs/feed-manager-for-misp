# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import abc
import collections
import datetime
import logging

from typing import Dict
from typing import List
from typing import Optional
from typing import Union

import feed_manager
from feed_manager import translator

try:
    import pymisp
except ImportError as ie:
    pymisp = None
    feed_manager.print_dependency_error_and_raise(ie)


class FeedGenerationException(Exception):
    """Generic exception."""


class FeedEventNotFound(FeedGenerationException):
    """Exception raised when the feed has not the required event."""


FeedEventMetadata = collections.namedtuple(
    "FeedEventMetadata",
    [
        "event_uuid",
        "event_bucket",
    ],
)


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


class FeedUtils:
    """Feed utilities."""

    @classmethod
    def get_event_metadata(
        cls,
        manifest: Dict,
        event_bucket: Optional[str] = None,
    ) -> FeedEventMetadata:
        """Get the metadata related to the event."""
        if event_bucket:
            for event_uuid, event_json in manifest.items():
                if event_json["date"] == event_bucket:
                    return FeedEventMetadata(
                        event_uuid=event_uuid,
                        event_bucket=event_json["date"],
                    )
            raise FeedEventNotFound
        else:
            dated_events = []
            for event_uuid, event_json in manifest.items():
                dated_events.append(
                    (
                        event_json["date"],
                        event_uuid,
                        event_json["info"],
                    )
                )
            # Sort by date then by event name
            dated_events.sort(key=lambda k: (k[0], k[2], k[1]), reverse=True)
            return FeedEventMetadata(
                event_uuid=dated_events[0][1],
                event_bucket=dated_events[0][0],
            )

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
        """Return whether the misp event contains a specific tag."""
        return any(cls.tag_equals(tag, misp_tag) for tag in misp_event.tags)


class AbstractFeedGenerator(abc.ABC):
    """Abstract class for every feed generators."""

    def __init__(self, storage_layer):
        """Constructor."""
        self._logger = logging.getLogger(__name__)
        self._storage_layer = storage_layer
        self._manifest = {}
        self._hashes = []

    @abc.abstractmethod
    def add_object(self, misp_object: pymisp.MISPObject) -> bool:
        """Add object to the feed."""

    @abc.abstractmethod
    def add_tag(self, misp_tag: pymisp.MISPTag) -> bool:
        """Add tag to the feed."""

    @abc.abstractmethod
    def add_attribute(self, attr_type: str, attr_value: str, **attr_data) -> bool:
        """Add an attribute to the feed."""

    @abc.abstractmethod
    def flush(self) -> None:
        """Flush the feed."""

    def _flush_event(
        self, event: pymisp.MISPEvent, update_manifest: Optional[bool] = True
    ) -> None:
        """Flush the event."""
        if update_manifest:
            self._manifest.update(event.manifest)
            self._storage_layer.save_manifest(self._manifest)
        self._storage_layer.save_event(event.uuid, event.to_feed())
        self._storage_layer.append_hashes(self._hashes)
        self._hashes.clear()

    def _add_hash(self, event: pymisp.MISPEvent, attr_type: str, attr_value: str) -> None:
        """Take the attribute properties and add a hash."""
        fake_attribute = pymisp.MISPAttribute()
        fake_attribute.from_dict(type=attr_type, value=attr_value)
        for hash_value in fake_attribute.hash_values("md5"):
            self._hashes.append([hash_value, event.get("uuid")])


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

    def set_clock(self, utc_now: Optional[datetime.datetime]) -> None:
        """Initialize the feed clock to the provided value or utcnow() otherwise."""
        if utc_now:
            self._event_date_callback = lambda: utc_now
        else:
            self._event_date_callback = lambda: datetime.datetime.utcnow()

    def __init__(
        self,
        storage_layer,
        feed_properties: Optional[FeedProperties] = None,
        date_override: Optional[datetime.datetime] = None,
    ):
        """Constructor."""
        super(PeriodicFeedGenerator, self).__init__(storage_layer)
        self._feed_properties = feed_properties or FeedProperties()
        # Let 'set_clock' initialize '_event_date_callback'
        self._event_date_callback = None
        # Set up the callback used to know the current date at which we are inserting items
        self.set_clock(date_override)

        # Load the manifest but create it in case it is empty
        self._logger.info("Loading feed manifest")
        try:
            self._manifest = self._storage_layer.load_manifest()
        except FileNotFoundError:
            self._logger.info("No manifest found; creating new manifest and first event")
            self._flush_event(self._create_event(self._get_current_bucket()))

        # Load the current event but load it if the existing manifest does not have it
        if date_override:
            event_bucket = self.get_bucket(date_override)
            self._logger.info(
                "Loading feed event with an overriden date/bucket: %s/%s",
                date_override,
                event_bucket,
            )
            try:
                event_metadata = FeedUtils.get_event_metadata(
                    manifest=self._manifest,
                    event_bucket=event_bucket,
                )
            except FeedEventNotFound:
                self._logger.info(
                    "No feed event found; creating new event at the request date/bucket: %s/%s",
                    date_override,
                    event_bucket,
                )
                self._flush_event(self._create_event(event_bucket))
                event_metadata = FeedUtils.get_event_metadata(
                    manifest=self._manifest,
                    event_bucket=event_bucket,
                )
        else:
            self._logger.info("Loading feed event with the latest date/bucket")
            event_metadata = FeedUtils.get_event_metadata(self._manifest)
        self._current_event_bucket = event_metadata.event_bucket
        self._current_event = self._load_event(event_metadata.event_uuid)

    def _get_current_bucket(self) -> str:
        """Get the current bucket (truncated datetime object)."""
        return self.get_bucket(self._event_date_callback())

    def _update_event(self) -> None:
        """Update the current bucket if needed."""
        event_bucket = self._get_current_bucket()
        if self._current_event_bucket != event_bucket:
            self._logger.info(
                "New event bucket required (current=%s, requested=%s)",
                self._current_event_bucket,
                event_bucket,
            )
            # flush previous event without updating manifest
            self._flush_event(self._current_event, update_manifest=False)
            self._current_event_bucket = event_bucket
            self._current_event = self._create_event(event_bucket)
            self._flush_event(self._current_event)

    def _create_event(self, event_bucket: str) -> pymisp.MISPEvent:
        """Create an event in the given bucket."""
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

    def _load_event(self, event_uuid: str) -> pymisp.MISPEvent:
        """Load the event."""
        data = self._storage_layer.load_event(event_uuid)
        event = pymisp.MISPEvent()
        event.from_dict(**data["Event"])
        return event

    ##
    # PUBLIC METHODS
    ##

    def add_object(self, misp_object: pymisp.MISPObject) -> bool:
        """Implement interface."""
        self._update_event()
        if FeedUtils.contains_object(self._current_event, misp_object):
            return False
        self._current_event.add_object(misp_object)
        for attribute in misp_object.attributes:
            self._add_hash(self._current_event, attribute.type, attribute.value)
        return True

    def add_attribute(self, attr_type: str, attr_value: str, **attr_data) -> bool:
        """Implement interface."""
        self._update_event()
        if FeedUtils.contains_attribute(self._current_event, attr_type, attr_value, **attr_data):
            return False
        self._current_event.add_attribute(attr_type, attr_value, **attr_data)
        self._add_hash(self._current_event, attr_type, attr_value)
        return True

    def add_tag(self, misp_tag: pymisp.MISPTag) -> bool:
        """Implement interface."""
        self._update_event()
        if FeedUtils.contains_tag(self._current_event, misp_tag):
            return False
        self._current_event.add_tag(misp_tag)
        return True

    def flush(self) -> None:
        """Implement interface."""
        self._flush_event(self._current_event)


class DailyFeedGenerator(PeriodicFeedGenerator):
    """A feed generator that creates a different event every day."""

    BUCKET_FMT = "%Y-%m-%d"

    @classmethod
    def get_bucket(cls, date_obj: datetime.datetime) -> str:
        """Implement interface."""
        return date_obj.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        ).strftime(cls.BUCKET_FMT)

    @classmethod
    def parse_bucket(cls, date_str: str) -> datetime.datetime:
        """Implement interface"""
        return datetime.datetime.strptime(date_str, cls.BUCKET_FMT)
