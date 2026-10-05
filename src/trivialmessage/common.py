# src/trivialmessage/common.py
import json
import mimetypes
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parseaddr
from os import PathLike
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional


def canonicalize_from_recipient(recipient: str | None) -> str | None:
    """
    Turn 'foo+username@bar.ext' into 'foo@bar.ext'.

    Accepts either raw emails or 'Name <addr@domain>'.
    Returns None if missing/unparseable.
    """
    if not recipient:
        return None

    _, addr = parseaddr(recipient)
    addr = (addr or recipient).strip()
    if "@" not in addr:
        return None

    local, domain = addr.split("@", 1)
    if "+" in local:
        local = local.split("+", 1)[0]

    return f"{local}@{domain}"


def _to_aware_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """
    Normalize datetimes to timezone-aware UTC.

    - If dt is naive, assume it's already UTC and attach tzinfo=UTC.
    - If dt is aware, convert to UTC.
    """
    if dt is None:
        return None
    try:
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        # Best effort fallback
        return dt.replace(tzinfo=timezone.utc)


def _norm_str(s: Any) -> str:
    """Case-insensitive normalization for filter comparisons."""
    return str(s or "").casefold()


def _norm_list(xs: Optional[List[Any]]) -> List[str]:
    return [_norm_str(x) for x in (xs or []) if str(x or "").strip()]


@dataclass
class MessageFilter:
    """Filters for message retrieval"""

    sender: Optional[str] = None
    recipient: Optional[str] = None  # for emails; channel_id for chat
    subject_contains: Optional[str] = None  # email only
    content_contains: Optional[str] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    thread_id: Optional[str] = None  # for threaded platforms

    folder: Optional[str] = None  # include: message must be in this folder
    exclude_folders: Optional[List[str]] = (
        None  # exclude: message must NOT be in any of these
    )

    def __post_init__(self) -> None:
        self.since = _to_aware_utc(self.since)
        self.until = _to_aware_utc(self.until)


@dataclass
class Message:
    """Unified message representation for all platforms"""

    # Core fields (always present)
    id: str
    platform_type: str  # 'gmail', 'slack', 'whatsapp', etc.
    content: str
    sender: str
    timestamp: datetime

    # Communication-specific fields (optional)
    #
    # `recipient` remains the backwards-compatible primary recipient:
    # - email: first/primary To address
    # - chat: channel
    #
    # Email adapters that know about multiple recipients may additionally
    # populate `recipients` below.
    recipient: Optional[str] = None
    subject: Optional[str] = None  # email only

    # Threading/conversation fields (optional)
    thread_id: Optional[str] = None
    conversation_id: Optional[str] = None
    in_reply_to: Optional[str] = None

    # Rich content (optional)
    html_content: Optional[str] = None
    attachments: Optional[List[Dict]] = None

    # - folder: a single "primary" folder (best-effort)
    # - folders: all known folders/roles/names this message belongs to
    folder: Optional[str] = None
    folders: Optional[List[str]] = None

    # Platform metadata (optional)
    raw_data: Optional[Dict] = None  # original platform response
    platform_metadata: Optional[Dict] = None  # platform-specific fields

    # All known recipients, when exposed by the platform.
    #
    # This is deliberately the final dataclass field so adding it does not
    # change the positional meaning of any existing Message(...) constructor
    # calls.
    #
    # Older adapters may leave this as None and populate only `recipient`.
    # Newer email adapters may populate it with all To/Cc/Bcc recipients.
    recipients: Optional[List[str]] = None

    def __post_init__(self) -> None:
        # Always store timestamps as aware UTC.
        self.timestamp = _to_aware_utc(self.timestamp) or datetime.now(timezone.utc)

    def all_recipients(self) -> List[str]:
        """
        Return every known recipient.

        The legacy singular `recipient` is always considered first, followed
        by entries from the newer plural `recipients` field.

        Values are de-duplicated case-insensitively while preserving their
        original spelling and order.
        """
        out: List[str] = []
        seen: set[str] = set()

        values = [self.recipient, *(self.recipients or [])]

        for value in values:
            if value is None:
                continue

            text = str(value).strip()
            if not text:
                continue

            key = text.casefold()

            if key in seen:
                continue

            seen.add(key)
            out.append(text)

        return out

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with proper datetime handling."""
        data = asdict(self)

        if self.timestamp:
            data["timestamp"] = _to_aware_utc(self.timestamp).isoformat()

        # Preserve the historical serialized shape for messages produced by
        # older/single-recipient adapters. The field appears only when an
        # adapter actually supplies plural recipient information.
        if self.recipients is None:
            data.pop("recipients", None)

        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str, indent=2)

    def matches_filter(self, filters: Optional[MessageFilter]) -> bool:
        if not filters:
            return True

        if filters.sender:
            if _norm_str(filters.sender) not in _norm_str(self.sender):
                return False

        if filters.recipient:
            wanted = _norm_str(filters.recipient)

            if not any(
                wanted in _norm_str(recipient) for recipient in self.all_recipients()
            ):
                return False

        if filters.subject_contains:
            if _norm_str(filters.subject_contains) not in _norm_str(self.subject):
                return False

        if filters.content_contains:
            combined = " ".join([self.content or "", self.html_content or ""])
            if _norm_str(filters.content_contains) not in _norm_str(combined):
                return False

        if filters.thread_id is not None:
            if str(self.thread_id) != str(filters.thread_id):
                return False

        # Time filtering (aware UTC comparisons)
        msg_ts = _to_aware_utc(self.timestamp)
        since = _to_aware_utc(filters.since)
        until = _to_aware_utc(filters.until)

        if msg_ts:
            if since and msg_ts < since:
                return False
            if until and msg_ts > until:
                return False

        # Folder filtering
        msg_folders = _norm_list(self.folders) + (
            [_norm_str(self.folder)] if self.folder else []
        )

        want = _norm_str(filters.folder) if filters.folder else ""

        if want:
            if want not in msg_folders:
                return False

        banned = set(_norm_list(filters.exclude_folders))

        if banned and any(f in banned for f in msg_folders):
            return False

        return True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Message":
        """
        Create Message from dictionary, handling datetime parsing + UTC
        normalization.

        This is automatically backwards/forwards compatible with `recipients`:
        old dictionaries omit it, while new dictionaries pass it through as a
        normal dataclass field.
        """
        d = dict(data or {})

        ts = d.get("timestamp")

        if isinstance(ts, str):
            try:
                parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                d["timestamp"] = _to_aware_utc(parsed)
            except ValueError:
                d["timestamp"] = datetime.now(timezone.utc)

        elif isinstance(ts, datetime):
            d["timestamp"] = _to_aware_utc(ts)

        else:
            d["timestamp"] = datetime.now(timezone.utc)

        valid_fields = {field.name for field in cls.__dataclass_fields__.values()}

        filtered_data = {k: v for k, v in d.items() if k in valid_fields}

        return cls(**filtered_data)

    def __str__(self) -> str:
        return (
            f"Message("
            f"{self.platform_type}:{self.id[:8]}... "
            f"from {self.sender}"
            f")"
        )

    def __repr__(self) -> str:
        return (
            f"Message(id='{self.id}', "
            f"platform='{self.platform_type}', "
            f"sender='{self.sender}', "
            f"timestamp={self.timestamp})"
        )


def apply_filters(
    messages: List[Message], filters: Optional[MessageFilter]
) -> List[Message]:
    """Apply filters to a list of messages."""
    if not filters:
        return messages
    return [msg for msg in messages if msg.matches_filter(filters)]


class MessagePlatform(ABC):
    """Unified interface for all messaging platforms"""

    @abstractmethod
    def get_unread(self, filters: Optional[MessageFilter] = None) -> List[Message]:
        """Get unread messages, optionally filtered."""
        raise NotImplementedError

    @abstractmethod
    def get_recent(
        self,
        limit: int = 10,
        since: Optional[datetime] = None,
        filters: Optional[MessageFilter] = None,
    ) -> List[Message]:
        """Get the N most recent messages, optionally since a time and with filters."""
        raise NotImplementedError

    @abstractmethod
    async def listen(
        self, filters: Optional[MessageFilter] = None, mark_read: bool = False
    ) -> AsyncIterator[Message]:
        """Async generator yielding new messages as they arrive."""
        raise NotImplementedError

    @abstractmethod
    def send(self, content: str, **kwargs) -> Message:
        """Send a message. Kwargs vary by platform. Returns the sent message."""
        raise NotImplementedError

    @abstractmethod
    def reply(self, original_message: Message, content: str, **kwargs) -> Message:
        """Reply to an original message via the same channel/method it came from."""
        raise NotImplementedError


class FixedSizeSet:
    def __init__(self, max_size):
        self.max_size = max_size
        self.set_data = set()
        self.deque_data = deque(maxlen=max_size)

    def add(self, item):
        if item not in self.set_data:
            if len(self.set_data) >= self.max_size:
                # Remove the oldest item from the deque and the set
                oldest_item = self.deque_data.popleft()
                self.set_data.remove(oldest_item)
            # Add the new item to both the deque and the set
            self.set_data.add(item)
            self.deque_data.append(item)

    def __contains__(self, item):
        return item in self.set_data

    def __len__(self):
        return len(self.set_data)


def _clean_attachment_filename(value: object) -> str:
    """
    Normalize an attachment filename to a basename suitable for transport APIs.

    Explicit dictionary filenames may be supplied independently of the local path,
    so strip both POSIX and Windows-style path components without otherwise
    modifying the filename.
    """
    filename = str(value or "").strip().replace("\\", "/").rsplit("/", 1)[-1]
    if not filename:
        raise ValueError("attachment filename is required")
    return filename


def normalize_attachment(attachment: object) -> dict:
    """
    Normalize one outbound attachment to:

        {
            "filename": str,
            "content_type": str,
            "data": bytes,
        }

    Accepted forms:

    - "path/to/file.pdf" (or any os.PathLike)
    - {
          "filename": "optional-name.pdf",
          "content_type": "optional/type",
          "data": b"...",
      }
    - the same dict with "data" set to a local path instead of bytes

    For path inputs, filename defaults to the local basename and content type is
    inferred with mimetypes. For direct byte data, filename is required so that
    the MIME type can be inferred and the recipient sees a useful attachment name.
    """
    if isinstance(attachment, (str, PathLike)):
        path = Path(attachment).expanduser()
        filename = _clean_attachment_filename(path.name)
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        return {
            "filename": filename,
            "content_type": content_type,
            "data": path.read_bytes(),
        }

    if not isinstance(attachment, dict):
        raise TypeError(
            "each attachment must be a local path or a dict with "
            "'filename', 'content_type', and 'data'"
        )

    raw_data = attachment.get("data")
    filename = attachment.get("filename")
    content_type = attachment.get("content_type")

    if isinstance(raw_data, (str, PathLike)):
        path = Path(raw_data).expanduser()
        data = path.read_bytes()
        if not filename:
            filename = path.name
    elif isinstance(raw_data, bytes):
        data = raw_data
    elif isinstance(raw_data, bytearray):
        data = bytes(raw_data)
    elif isinstance(raw_data, memoryview):
        data = raw_data.tobytes()
    else:
        raise TypeError(
            "attachment dict 'data' must be bytes, bytearray, memoryview, "
            "or a local path"
        )

    filename = _clean_attachment_filename(filename)

    if content_type is None or not str(content_type).strip():
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    else:
        content_type = str(content_type).strip()

    return {
        "filename": filename,
        "content_type": content_type,
        "data": data,
    }


def normalize_attachments(attachments: object) -> List[dict]:
    """
    Normalize the public `attachments=` argument.

    `attachments` may be:
      - one local path
      - one attachment dict
      - any iterable of local paths and/or attachment dicts

    A top-level bytes value is intentionally rejected because it has no filename.
    Use {"filename": "...", "data": bytes_value} for in-memory data.
    """
    if attachments is None:
        return []

    if isinstance(attachments, (str, PathLike, dict)):
        values = [attachments]
    elif isinstance(attachments, (bytes, bytearray, memoryview)):
        raise TypeError(
            "a raw bytes attachment needs a filename; pass "
            "{'filename': '...', 'data': bytes_value}"
        )
    else:
        try:
            values = list(attachments)
        except TypeError as exc:
            raise TypeError(
                "attachments must be a local path, an attachment dict, "
                "or an iterable of those values"
            ) from exc

    return [normalize_attachment(value) for value in values]
