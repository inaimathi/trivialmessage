# src/trivialmessage/common.py
import json
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parseaddr
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
    recipient: Optional[str] = None  # email: to field, chat: channel
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

    def __post_init__(self) -> None:
        # Always store timestamps as aware UTC.
        self.timestamp = _to_aware_utc(self.timestamp) or datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with proper datetime handling."""
        data = asdict(self)
        if self.timestamp:
            data["timestamp"] = _to_aware_utc(self.timestamp).isoformat()
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
            if _norm_str(filters.recipient) not in _norm_str(self.recipient):
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

        # NEW: folder filtering
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
        """Create Message from dictionary, handling datetime parsing + UTC normalization."""
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
        return f"Message({self.platform_type}:{self.id[:8]}... from {self.sender})"

    def __repr__(self) -> str:
        return (
            f"Message(id='{self.id}', platform='{self.platform_type}', "
            f"sender='{self.sender}', timestamp={self.timestamp})"
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
