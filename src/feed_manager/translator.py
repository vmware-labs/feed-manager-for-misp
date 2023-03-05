# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import datetime
import itertools
import feed_manager

from typing import List
from typing import Generator
from typing import Iterable
from typing import Optional
from typing import Tuple
from typing import Union


try:
    import pymisp
except ImportError as ie:
    pymisp = None
    feed_manager.print_dependency_error_and_raise(ie)


class TagUtils:
    """Class with utility methods to handle tags."""

    # map object name to the attribute used to store object tags
    OBJECT_NAME_TO_ATTRIBUTE_TAG = {
        "file": "filename",
        "network-profile": "text",
        "sandbox-report": "score",
        "atp-report": "score",
    }

    @classmethod
    def __workaround_bug(cls, object_attribute: pymisp.MISPAttribute) -> pymisp.MISPAttribute:
        """Workaround the current pymisp bug where object attributes have mis-initialized tags."""
        if object_attribute.tags:
            return object_attribute
        if not hasattr(object_attribute, "AttributeTag"):
            return object_attribute
        tags = []
        try:
            for attribute_tag in object_attribute.AttributeTag:
                tag = attribute_tag["Tag"]
                tag_object = pymisp.MISPTag()
                tag_object.from_dict(**tag)
                tags.append(tag_object)
        except KeyError:
            pass
        was_edited = object_attribute.edited
        object_attribute.tags = tags
        if not was_edited:
            object_attribute.edited = False
        return object_attribute

    @classmethod
    def get_taggable_entity(
        cls,
        entity: Union[pymisp.MISPEvent, pymisp.MISPObject, pymisp.MISPAttribute],
    ) -> Union[pymisp.MISPEvent, pymisp.MISPAttribute]:
        """Get the taggable entity."""
        if isinstance(entity, pymisp.MISPEvent):
            return entity
        elif isinstance(entity, pymisp.MISPAttribute):
            return entity
        else:
            try:
                attribute_type = cls.OBJECT_NAME_TO_ATTRIBUTE_TAG[entity.name]
            except KeyError:
                raise ValueError(f"Can not process object '{entity.name}/{entity.uuid}'")
            try:
                return cls.__workaround_bug(entity.get_attributes_by_relation(attribute_type)[0])
            except IndexError:
                raise ValueError(f"Object '{entity.name}/{entity.uuid}' seems malformed'")

    @classmethod
    def validate_tag(cls, input_object: Union[pymisp.MISPTag, str]) -> pymisp.MISPTag:
        """Validate a tag (whether an object or a string) and return an object."""
        if isinstance(input_object, pymisp.MISPTag):
            return input_object
        else:
            return cls.create_tag(name=input_object)

    @classmethod
    def create_tag(cls, name: str, colour: Optional[str] = None) -> pymisp.MISPTag:
        """Create a tag."""
        tag = pymisp.MISPTag()
        tag.from_dict(
            name=name,
            colour=colour,
        )
        return tag

    @classmethod
    def add_tag(
        cls,
        entity: Union[pymisp.MISPAttribute, pymisp.MISPObject, pymisp.MISPEvent],
        tag: Union[str, pymisp.MISPTag],
    ):
        """Add a tag to a MISP entity, either an event, an object, or an attribute."""
        tag = cls.validate_tag(tag)
        taggable_entity = cls.get_taggable_entity(entity)
        taggable_entity.add_tag(tag)

    @classmethod
    def entity_contains_tag(
        cls,
        entity: Union[pymisp.MISPEvent, pymisp.MISPObject, pymisp.MISPAttribute],
        tag_name: str,
    ) -> bool:
        """Whether an entity is tagged with a given tag."""
        entity = cls.get_taggable_entity(entity)
        return any(tag.name == tag_name for tag in entity.tags)

    @classmethod
    def entity_contains_any_tags(
        cls,
        entity: Union[pymisp.MISPEvent, pymisp.MISPObject, pymisp.MISPAttribute],
        tag_names: List[str],
    ) -> bool:
        """Whether an entity is tagged with any of the given tags."""
        return any(cls.entity_contains_tag(entity, tag_name) for tag_name in tag_names)

    @classmethod
    def get_cluster_category_and_value(
        cls,
        tag: Union[str, pymisp.MISPTag],
    ) -> Tuple[Optional[str], Optional[str]]:
        """Decode a galaxy cluster tag into category and value."""
        if isinstance(tag, pymisp.MISPTag):
            tag = tag.name
        try:
            category, value = tag.split("=")
            return category, value.strip('"')
        except (KeyError, IndexError, ValueError):
            return None, None

    @classmethod
    def get_cluster_galaxy_and_value(
        cls,
        tag: Union[str, pymisp.MISPTag],
    ) -> Tuple[Optional[str], Optional[str]]:
        """Decode a galaxy cluster tag into category and value."""
        if isinstance(tag, pymisp.MISPTag):
            tag = tag.name
        category, value = cls.get_cluster_category_and_value(tag)
        if category is None and value is None:
            return None, None
        if not category.startswith("misp-galaxy:"):
            return None, None
        category = category.replace("misp-galaxy:", "")
        return category, value

    @classmethod
    def get_cluster_tag_value(
        cls,
        tag: Union[str, pymisp.MISPTag],
        category: str = None,
    ) -> Optional[str]:
        """Get the value of a galaxy cluster tag optionally filtering by category."""
        tag_category, tag_value = cls.get_cluster_category_and_value(tag)
        if category and tag_category:
            return tag_value if tag_category.startswith(category) else None
        else:
            return tag_value

    @classmethod
    def iter_tags(cls, event: pymisp.MISPEvent) -> Generator[pymisp.MISPTag, None, None]:
        """Iterate over all tags."""
        for tag in event.tags:
            yield tag
        for entity in itertools.chain(event.objects, event.attributes):
            try:
                taggable_entity = cls.get_taggable_entity(entity)
                for tag in taggable_entity.tags:
                    yield tag
            except ValueError:
                pass


class SightingUtils:
    """Utility class to deal with sightings and timestamps."""

    DATETIME_FMT = "%Y-%m-%d %H:%M:%S"

    @classmethod
    def format_sighting(
        cls,
        sighting_object: pymisp.MISPSighting,
        fmt: Optional[str] = None,
    ) -> str:
        """Format a sighting into a string."""
        if not fmt:
            fmt = cls.DATETIME_FMT
        return cls.timestamp_to_date(cls.sighting_to_timestamp(sighting_object)).strftime(fmt)

    @classmethod
    def format_seen_times(
        cls,
        misp_object: pymisp.MISPObject,
        fmt: Optional[str] = None,
    ) -> str:
        """Format first and last seen"""
        if not fmt:
            fmt = cls.DATETIME_FMT
        return "first={}/last={}".format(
            misp_object.first_seen.strftime(fmt), misp_object.last_seen.strftime(fmt)
        )

    @classmethod
    def is_datetime_naive(cls, date_object: datetime.datetime) -> bool:
        """Return whether a datetime object is naive (not TZ info)."""
        return date_object.tzinfo is None or date_object.tzinfo.utcoffset(date_object) is None

    @classmethod
    def timestamp_to_date(cls, timestamp: int) -> datetime.datetime:
        """Convert a timestamp to datetime object."""
        return datetime.datetime.utcfromtimestamp(timestamp).replace(tzinfo=datetime.timezone.utc)

    @classmethod
    def sighting_to_timestamp(cls, sighting_object: pymisp.MISPSighting) -> int:
        """Get the timestamp of a sighting object."""
        try:
            # Initialized Sightings have a 'date_sighting' attribute
            return int(sighting_object.date_sighting)
        except AttributeError:
            # Uninitialized Sightings have a 'timestamp' attribute
            return int(sighting_object.timestamp)

    @classmethod
    def get_sightings(
        cls, entity: Union[pymisp.MISPAttribute, pymisp.MISPObject]
    ) -> List[pymisp.MISPSighting]:
        """Get the all the sightings from an entity."""
        return TagUtils.get_taggable_entity(entity).Sighting

    @classmethod
    def get_sightings_date(
        cls, entity: Union[pymisp.MISPAttribute, pymisp.MISPObject]
    ) -> List[datetime.datetime]:
        """Get all sightings as datetime objects."""
        return [
            cls.timestamp_to_date(cls.sighting_to_timestamp(x)) for x in cls.get_sightings(entity)
        ]

    @classmethod
    def get_sightings_timestamp(
        cls, entity: Union[pymisp.MISPAttribute, pymisp.MISPObject]
    ) -> List[int]:
        """Get all sightings as timestamps."""
        return [cls.sighting_to_timestamp(x) for x in cls.get_sightings(entity)]

    @classmethod
    def date_to_sightings(
        cls,
        date_objects: Iterable[datetime.datetime],
    ) -> List[pymisp.MISPSighting]:
        """Update sightings."""
        sighting_objects = []
        for date_object in date_objects:
            sighting = pymisp.MISPSighting()
            sighting.from_dict(**{"timestamp": date_object.timestamp()})
            sighting_objects.append(sighting)
        return sighting_objects

    @classmethod
    def has_sighting(
        cls,
        entity: Union[pymisp.MISPAttribute, pymisp.MISPObject],
        sighting: pymisp.MISPSighting,
    ) -> bool:
        """Return whether the object has a sighting with this timestamp."""
        existing_timestamps = set(cls.get_sightings_timestamp(entity))
        return cls.sighting_to_timestamp(sighting) in existing_timestamps

    @classmethod
    def iter_sightings(
        cls,
        event: pymisp.MISPEvent,
    ) -> Generator[pymisp.MISPSighting, None, None]:
        """Iterate over all sightings."""
        for entity in itertools.chain(event.objects, event.attributes):
            try:
                for sighting in cls.get_sightings_date(entity):
                    yield sighting
            except ValueError:
                pass

    @classmethod
    def update_object_seen_times(
        cls,
        misp_object: pymisp.MISPObject,
        date_objects: Iterable[datetime.datetime],
    ) -> pymisp.MISPObject:
        """Update seen times of an object given a list of date objects."""
        if any(cls.is_datetime_naive(x) for x in date_objects):
            raise ValueError("Parameter 'date_objects' must contain timezone aware objects only")
        first_seen = min(date_objects)
        if (
            not hasattr(misp_object, "first_seen")
            or not misp_object.first_seen
            or first_seen < misp_object.first_seen
        ):
            misp_object.first_seen = first_seen
            misp_object.edited = True
        last_seen = max(date_objects)
        if (
            not hasattr(misp_object, "last_seen")
            or not misp_object.last_seen
            or last_seen > misp_object.last_seen
        ):
            misp_object.last_seen = last_seen
            misp_object.edited = True
        return misp_object


class IndicatorTranslator:
    """Class that translate indicators or telemetry events to MISP objects."""

    DEFAULT_FILE_ATTRIBUTE_CATEGORY = "Payload delivery"
    DEFAULT_NET_ATTRIBUTE_CATEGORY = "Network activity"
    DEFAULT_FILE_NAME = "unknown"

    @classmethod
    def to_network_attribute(
        cls,
        network_indicator: str,
        tags: Optional[List[Union[str, pymisp.MISPTag]]] = None,
    ) -> pymisp.MISPAttribute:
        """Get a network indicator as attribute."""
        if "://" in network_indicator:
            attribute_type = "url"
        elif len(network_indicator.split(".")) == 4:
            if ":" in network_indicator:
                attribute_type = "ip-dst|port"
            else:
                attribute_type = "ip"
        else:
            attribute_type = "domain"
        net_attribute = pymisp.MISPAttribute()
        net_attribute.from_dict(
            type=attribute_type,
            category=cls.DEFAULT_NET_ATTRIBUTE_CATEGORY,
            value=network_indicator,
        )
        for tag in tags or []:
            TagUtils.add_tag(net_attribute, tag)
        return net_attribute

    @classmethod
    def to_file_attribute(
        cls,
        file_hash,
        attribute_category: str = DEFAULT_FILE_ATTRIBUTE_CATEGORY,
        tags: Optional[List[Union[str, pymisp.MISPTag]]] = None,
    ) -> pymisp.MISPAttribute:
        """Get a file attribute (useful when only a single hash is available)."""
        attribute_type = feed_manager.get_hash_type(file_hash)
        if not attribute_type:
            raise ValueError(f"Invalid hash '{file_hash}'")
        file_attribute = pymisp.MISPAttribute()
        file_attribute.from_dict(
            type=attribute_type,
            category=attribute_category,
            value=file_hash,
        )
        for tag in tags or []:
            TagUtils.add_tag(file_attribute, tag)
        return file_attribute

    @classmethod
    def to_file_object(
        cls,
        file_md5: str,
        file_sha1: str,
        file_sha256: str,
        file_name: Optional[str] = None,
        size: Optional[int] = None,
        mime_type: Optional[str] = None,
        comment: Optional[str] = None,
        attribute_category: str = DEFAULT_FILE_ATTRIBUTE_CATEGORY,
        tags: Optional[List[Union[str, pymisp.MISPTag]]] = None,
    ) -> pymisp.MISPObject:
        """Get a file object (mandatory when having multiple hashes)."""
        file_object = pymisp.MISPObject(name="file")
        file_object.add_attribute(
            "filename",
            value=file_name or cls.DEFAULT_FILE_NAME,
            comment=comment,
            to_ids=False,
        )
        if file_md5:
            file_object.add_attribute(
                "md5",
                value=file_md5,
                category=attribute_category,
                to_ids=True,
            )
        if file_sha1:
            file_object.add_attribute(
                "sha1",
                value=file_sha1,
                category=attribute_category,
                to_ids=True,
            )
        if file_sha256:
            file_object.add_attribute(
                "sha256",
                value=file_sha256,
                category=attribute_category,
                to_ids=True,
            )
        if size:
            file_object.add_attribute(
                "size-in-bytes",
                value=size,
                category=attribute_category,
                to_ids=False,
            )
        if mime_type:
            file_object.add_attribute(
                "mimetype",
                value=mime_type,
                category=attribute_category,
                to_ids=False,
            )
        for tag in tags or []:
            TagUtils.add_tag(file_object, tag)
        return file_object
