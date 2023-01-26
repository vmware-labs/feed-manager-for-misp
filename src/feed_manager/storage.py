import abc
import csv
import logging
import json
import os
import pathlib
import requests
from google.cloud import storage as google_storage

from typing import Dict
from typing import List
from typing import Optional
from typing import TextIO
from typing import Union


def get_storage_layer(
    input_string: str,
    path: Optional[str] = None,
    read_write: Optional[bool] = False,
):
    """Utility method to get the storage layer given some options."""

    # http readers start with http
    if input_string.startswith("http"):
        return ReadOnlyHttpStorage(base_url=input_string)

    # local storage require a directory
    if os.path.isdir(input_string):
        feed_path = os.path.join(input_string, path or "")
        pathlib.Path(feed_path).mkdir(parents=True, exist_ok=True)
        if read_write:
            return ReadWriteLocalStorage(local_dir=feed_path)
        else:
            return ReadOnlyLocalStorage(local_dir=feed_path)

    # google storage uses bucket:config_file notation
    try:
        bucket, config_file = input_string.split(":")
        if read_write:
            return ReadWriteGoogleStorage(
                config_file=config_file,
                bucket_name=bucket,
                path=path,
            )
        else:
            return ReadOnlyGoogleStorage(
                config_file=config_file,
                bucket_name=bucket,
                path=path,
            )
    except ValueError:
        pass

    raise RuntimeError("Could not decode the storage layer from '%s'" % input_string)


class AbstractReader(abc.ABC):
    """Abstract reader."""

    HASHES_FILENAME = "hashes.csv"

    MANIFEST_FILENAME = "manifest.json"

    @classmethod
    def _parse_csv(cls, csv_data: Union[TextIO, List]) -> List[List[str]]:
        """Parse a CSV file."""
        if not csv_data:
            return []
        # skip empty lines and skip lines with just whitespace
        return [[row[0], row[1]] for row in csv.reader(csv_data) if row and row[0].strip()]

    def __init__(self, path: Optional[str] = None) -> None:
        self._path = path or ""
        self._logger = logging.getLogger(__name__)

    def _get_object_path(self, object_name) -> str:
        """Return the object name."""
        return os.path.join(self._path, object_name)

    @abc.abstractmethod
    def load_manifest(self) -> Dict:
        """Load manifest."""

    @abc.abstractmethod
    def load_event(self, event_uuid: str) -> Dict:
        """Load event."""

    @abc.abstractmethod
    def load_hashes(self) -> List[List[str]]:
        """Load hashes."""


class AbstractWriter(AbstractReader, abc.ABC):
    """Abstract writer."""

    @abc.abstractmethod
    def save_event(self, event_uuid: str, event_feed: Dict) -> None:
        """Save event."""

    @abc.abstractmethod
    def save_manifest(self, manifest: Dict) -> None:
        """Save manifest."""

    @abc.abstractmethod
    def save_hashes(self, attribute_hashes: List[List[str]]) -> None:
        """Save hashes."""

    def append_hashes(self, attribute_hashes: List[List[str]]) -> None:
        """Append hashes."""
        if not attribute_hashes:
            return
        hashes = self.load_hashes()
        hashes.extend(attribute_hashes)
        self.save_hashes(hashes)


class ReadOnlyLocalStorage(AbstractReader):
    """Read only storage from local directory."""

    def __init__(self, local_dir: str) -> None:
        """Constructor."""
        super().__init__(path=local_dir)

    def load_manifest(self) -> Dict:
        """Implement interface."""
        with open(self._get_object_path(self.MANIFEST_FILENAME), "r") as f:
            return json.load(f)

    def load_event(self, event_uuid: str) -> Dict:
        """Implement interface."""
        with open(self._get_object_path(f"{event_uuid}.json"), "r") as f:
            return json.load(f)

    def load_hashes(self) -> List[List[str]]:
        """Load hashes."""
        try:
            with open(self._get_object_path(self.HASHES_FILENAME), "r") as csv_file:
                return self._parse_csv(csv_file)
        except FileNotFoundError:
            return []


class ReadOnlyHttpStorage(AbstractReader):
    """Consumer using a remote (HTTP) source."""

    DEFAULT_TIMEOUT = 60

    def __init__(self, base_url: str) -> None:
        """Constructor."""
        super().__init__(path=None)
        self._base_url = base_url.rstrip("/")

    def _get_object_path(self, object_name: str) -> str:
        """Override method."""
        return f"{self._base_url}/{object_name}"

    def _download_data(self, object_name: str) -> requests.Response:
        """Download data from HTTP."""
        response = requests.get(self._get_object_path(object_name), timeout=self.DEFAULT_TIMEOUT)
        if response.status_code == 404:
            raise FileNotFoundError
        else:
            return response

    def load_manifest(self) -> Dict:
        """Implement interface."""
        return self._download_data(self.MANIFEST_FILENAME).json()

    def load_event(self, event_uuid: str) -> Dict:
        """Implement interface."""
        return self._download_data(f"{event_uuid}.json").json()

    def load_hashes(self) -> List[List[str]]:
        """Implement interface."""
        try:
            return self._parse_csv(self._download_data(self.HASHES_FILENAME).text.split("\n"))
        except FileNotFoundError:
            return []


class ReadOnlyGoogleStorage(AbstractReader):
    """Consumer using Google Storage."""

    def __init__(self, config_file: str, bucket_name: str, path: Optional[str] = None) -> None:
        """Constructor."""
        super().__init__(path=path)
        self._client = google_storage.Client.from_service_account_json(
            json_credentials_path=config_file,
        )
        self._bucket = self._client.bucket(bucket_name)

    def _download_data(self, object_name: str) -> str:
        """Download data from the bucket."""
        try:
            return self._bucket.get_blob(self._get_object_path(object_name)).download_as_text()
        except AttributeError:
            raise FileNotFoundError

    def load_manifest(self) -> Dict:
        """Implement interface."""
        return json.loads(self._download_data(self.MANIFEST_FILENAME))

    def load_event(self, event_uuid: str) -> Dict:
        """Implement interface."""
        return json.loads(self._download_data(f"{event_uuid}.json"))

    def load_hashes(self) -> List[List[str]]:
        try:
            return self._parse_csv(self._download_data(self.HASHES_FILENAME).split("\n"))
        except FileNotFoundError:
            return []


##
# WRITERS
##


class ReadWriteLocalStorage(ReadOnlyLocalStorage, AbstractWriter):
    """Writer using local storage."""

    def save_event(self, event_uuid: str, event_feed: Dict) -> None:
        """Implement interface."""
        with open(self._get_object_path(f"{event_uuid}.json"), "w") as f:
            json.dump(event_feed, f, indent=True)

    def save_manifest(self, manifest: Dict) -> None:
        """Implement interface."""
        with open(self._get_object_path(self.MANIFEST_FILENAME), "w") as f:
            json.dump(manifest, f, indent=True)

    def save_hashes(self, attribute_hashes: List[List[str]]) -> None:
        """Implement interface."""
        with open(self._get_object_path(self.HASHES_FILENAME), "w") as f:
            for element in attribute_hashes:
                f.write(f"{element[0]},{element[1]}\n")

    def append_hashes(self, attribute_hashes: List[List[str]]) -> None:
        """Override method."""
        with open(self._get_object_path(self.HASHES_FILENAME), "a") as f:
            for element in attribute_hashes:
                f.write(f"{element[0]},{element[1]}\n")


class ReadWriteGoogleStorage(ReadOnlyGoogleStorage, AbstractWriter):
    """Writer to Google Storage buckets."""

    def _upload_data(self, object_name: str, data: str) -> None:
        """Upload data to the bucket."""
        blob = self._bucket.blob(self._get_object_path(object_name))
        blob.upload_from_string(data)

    def save_event(self, event_uuid: str, event_feed: Dict) -> None:
        """Implement interface."""
        self._upload_data(object_name=f"{event_uuid}.json", data=json.dumps(event_feed))

    def save_manifest(self, manifest: Dict) -> None:
        """Implement interface."""
        self._upload_data(object_name=self.MANIFEST_FILENAME, data=json.dumps(manifest))

    def save_hashes(self, attribute_hashes: List[List[str]]) -> None:
        """Implement interface."""
        data = [f"{element[0]},{element[1]}" for element in attribute_hashes]
        self._upload_data(object_name=self.HASHES_FILENAME, data="\n".join(data))
