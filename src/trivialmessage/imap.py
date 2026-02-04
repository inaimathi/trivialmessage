# src/trivialmessage/imap.py
import asyncio
import email
import imaplib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import AsyncIterator, List, Optional, Tuple

from .common import Message, MessageFilter, MessagePlatform


class IMAPPlatform(MessagePlatform):
    """
    Generic IMAP implementation for receiving emails from any IMAP server.

    Notes:
      - Uses UID commands (imap.uid(...)) and tracks UIDVALIDITY + last seen UID.
      - This is still polling-based. IMAP IDLE can be added later.
    """

    def __init__(
        self,
        imap_server: str,
        username: str,
        password: str,
        imap_port: int = 993,
        use_ssl: bool = True,
        mailbox: str = "INBOX",
    ):
        self.imap_server = imap_server
        self.username = username
        self.password = password
        self.imap_port = imap_port
        self.use_ssl = use_ssl
        self.mailbox = mailbox

    def _create_imap_connection(self) -> imaplib.IMAP4:
        """Create and authenticate IMAP connection + select mailbox."""
        if self.use_ssl:
            imap = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
        else:
            imap = imaplib.IMAP4(self.imap_server, self.imap_port)

        imap.login(self.username, self.password)
        typ, _ = imap.select(self.mailbox)
        if typ != "OK":
            try:
                imap.logout()
            except Exception:
                pass
            raise OSError(
                f"Failed to select mailbox {self.mailbox!r} on {self.imap_server}"
            )
        return imap

    def _imap_response_int(self, imap: imaplib.IMAP4, key: str) -> Optional[int]:
        """
        Read integer untagged response values like UIDVALIDITY/UIDNEXT after SELECT.
        """
        try:
            typ, data = imap.response(key)
            if typ == "OK" and data and data[0]:
                # e.g. b'12345'
                return int(data[0])
        except Exception:
            pass
        return None

    def _build_imap_search_criteria(
        self, base_criteria: List[str], filters: Optional[MessageFilter]
    ) -> List[str]:
        """
        Convert MessageFilter to IMAP search criteria tokens.
        (These tokens are later passed as separate args to imap.uid('search', None, *criteria))
        """
        criteria = list(base_criteria or [])

        if not filters:
            return criteria

        if filters.sender:
            criteria.extend(["FROM", f'"{filters.sender}"'])
        if filters.recipient:
            criteria.extend(["TO", f'"{filters.recipient}"'])
        if filters.subject_contains:
            criteria.extend(["SUBJECT", f'"{filters.subject_contains}"'])
        if filters.content_contains:
            criteria.extend(["BODY", f'"{filters.content_contains}"'])

        # IMAP SINCE/BEFORE are date-only
        if filters.since:
            since_utc = filters.since.astimezone(timezone.utc)
            criteria.extend(["SINCE", since_utc.strftime("%d-%b-%Y")])
        if filters.until:
            until_utc = filters.until.astimezone(timezone.utc)
            criteria.extend(["BEFORE", until_utc.strftime("%d-%b-%Y")])

        return criteria

    def _parse_ts(self, date_str: str) -> datetime:
        ts = datetime.now(timezone.utc)
        if not date_str:
            return ts
        try:
            ts2 = parsedate_to_datetime(date_str)
            if ts2.tzinfo is None or ts2.tzinfo.utcoffset(ts2) is None:
                ts2 = ts2.replace(tzinfo=timezone.utc)
            return ts2.astimezone(timezone.utc)
        except Exception:
            return ts

    def _convert_imap_message(self, msg_data: bytes, uid: str) -> Message:
        """Convert raw RFC822 bytes to Message."""
        msg = email.message_from_bytes(msg_data)

        subject = msg.get("Subject", "") or ""
        sender = msg.get("From", "") or ""
        recipient = msg.get("To", "") or ""
        date_str = msg.get("Date", "") or ""
        message_id = msg.get("Message-ID", "") or ""

        timestamp = self._parse_ts(date_str)

        text_content = ""
        html_content = ""

        def decode_part(part) -> str:
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    return ""
                charset = part.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="ignore")
            except Exception:
                try:
                    payload = part.get_payload(decode=True)
                    return payload.decode("utf-8", errors="ignore") if payload else ""
                except Exception:
                    return ""

        if msg.is_multipart():
            for part in msg.walk():
                ctype = (part.get_content_type() or "").lower()
                if ctype == "text/plain" and not text_content:
                    text_content = decode_part(part)
                elif ctype == "text/html" and not html_content:
                    html_content = decode_part(part)
        else:
            ctype = (msg.get_content_type() or "").lower()
            body = decode_part(msg)
            if ctype == "text/plain":
                text_content = body
            elif ctype == "text/html":
                html_content = body
            else:
                text_content = body

        return Message(
            id=str(uid),
            platform_type="imap",
            content=text_content or "",
            sender=sender,
            timestamp=timestamp,
            recipient=recipient,
            subject=subject,
            html_content=(
                html_content if html_content and html_content != text_content else None
            ),
            in_reply_to=msg.get("In-Reply-To"),
            raw_data={
                "uid": uid,
                "rfc822": None,
            },  # keep raw bytes out of JSON by default
            platform_metadata={
                "message_id": message_id,
                "cc": msg.get("Cc"),
                "bcc": msg.get("Bcc"),
                "reply_to": msg.get("Reply-To"),
                "content_type": msg.get_content_type(),
                "imap_server": self.imap_server,
                "mailbox": self.mailbox,
            },
        )

    def _uid_search(self, imap: imaplib.IMAP4, criteria: List[str]) -> List[str]:
        """Run a UID SEARCH and return list of UID strings."""
        typ, data = imap.uid("search", None, *criteria)  # type: ignore[arg-type]
        if typ != "OK" or not data or not data[0]:
            return []
        # data[0] is b'1 2 3'
        return [x.decode("utf-8") for x in data[0].split() if x]

    def _uid_fetch_rfc822(self, imap: imaplib.IMAP4, uid: str) -> Optional[bytes]:
        """Fetch RFC822 bytes for a UID."""
        typ, data = imap.uid("fetch", uid, "(RFC822)")
        if typ != "OK" or not data:
            return None
        for item in data:
            if (
                isinstance(item, tuple)
                and len(item) >= 2
                and isinstance(item[1], (bytes, bytearray))
            ):
                return bytes(item[1])
        return None

    def _fetch_messages(
        self, search_criteria: List[str], limit: Optional[int] = None
    ) -> List[Message]:
        """Fetch messages for UID SEARCH criteria."""
        imap = self._create_imap_connection()
        try:
            uids = self._uid_search(imap, search_criteria)
            if not uids:
                return []

            # IMAP SEARCH order is generally ascending; take most recent UIDs by tail.
            if limit is not None and limit > 0:
                uids = uids[-limit:]

            messages: List[Message] = []
            for uid in uids:
                raw = self._uid_fetch_rfc822(imap, uid)
                if not raw:
                    continue
                try:
                    messages.append(self._convert_imap_message(raw, uid))
                except Exception as e:
                    print(f"Error converting IMAP message uid={uid}: {e}")
            return messages
        finally:
            try:
                imap.logout()
            except Exception:
                pass

    def get_unread(self, filters: Optional[MessageFilter] = None) -> List[Message]:
        """Get unread messages."""
        criteria = self._build_imap_search_criteria(["UNSEEN"], filters)
        messages = self._fetch_messages(criteria)
        return [m for m in messages if m.matches_filter(filters)]

    def get_recent(
        self,
        limit: int = 10,
        since: Optional[datetime] = None,
        filters: Optional[MessageFilter] = None,
    ) -> List[Message]:
        """Get recent messages."""
        merged = filters or MessageFilter()
        if since:
            merged.since = (
                since.astimezone(timezone.utc)
                if since.tzinfo
                else since.replace(tzinfo=timezone.utc)
            )

        criteria = self._build_imap_search_criteria(["ALL"], merged)
        messages = self._fetch_messages(criteria, limit=limit)

        messages = [m for m in messages if m.matches_filter(merged)]
        messages.sort(key=lambda m: m.timestamp, reverse=True)
        return messages[:limit]

    async def listen(
        self, filters: Optional[MessageFilter] = None, mark_read: bool = False
    ) -> AsyncIterator[Message]:
        """
        Listen for new messages via polling, tracking UIDVALIDITY + last seen UID.

        Behavior: on startup, it will *not* replay the whole mailbox; it will begin
        yielding messages that arrive after the listener starts.
        """
        last_uid_seen = 0
        uidvalidity: Optional[int] = None

        # Initialize "cursor" using UIDNEXT so we don't replay existing messages.
        imap = self._create_imap_connection()
        try:
            uidvalidity = self._imap_response_int(imap, "UIDVALIDITY")
            uidnext = self._imap_response_int(imap, "UIDNEXT")
            if uidnext and uidnext > 0:
                last_uid_seen = uidnext - 1
        finally:
            try:
                imap.logout()
            except Exception:
                pass

        while True:
            try:
                imap = self._create_imap_connection()
                try:
                    current_uidvalidity = self._imap_response_int(imap, "UIDVALIDITY")
                    current_uidnext = self._imap_response_int(imap, "UIDNEXT")

                    # If UIDVALIDITY changes, all UID cursors are invalid.
                    if uidvalidity is None:
                        uidvalidity = current_uidvalidity
                    elif (
                        current_uidvalidity is not None
                        and current_uidvalidity != uidvalidity
                    ):
                        uidvalidity = current_uidvalidity
                        if current_uidnext and current_uidnext > 0:
                            last_uid_seen = current_uidnext - 1
                        else:
                            last_uid_seen = 0

                    # Build criteria for "new UIDs since last seen"
                    base = ["UID", f"{last_uid_seen + 1}:*"]
                    criteria = self._build_imap_search_criteria(base, filters)

                    uids = self._uid_search(imap, criteria)
                    for uid in uids:
                        try:
                            raw = self._uid_fetch_rfc822(imap, uid)
                            if not raw:
                                continue
                            msg = self._convert_imap_message(raw, uid)
                            if msg.matches_filter(filters):
                                if mark_read:
                                    # Mark as read using UID STORE
                                    try:
                                        imap.uid("store", uid, "+FLAGS", "(\\Seen)")
                                    except Exception:
                                        pass
                                yield msg
                            # Regardless of filter match, advance cursor to avoid re-fetching forever
                            try:
                                last_uid_seen = max(last_uid_seen, int(uid))
                            except Exception:
                                pass
                        except Exception as e:
                            print(f"Error processing IMAP uid={uid}: {e}")
                            continue
                finally:
                    try:
                        imap.logout()
                    except Exception:
                        pass

                await asyncio.sleep(30)

            except Exception as e:
                print(f"IMAP listen error: {e}")
                await asyncio.sleep(60)

    def send(self, content: str, **kwargs) -> Message:
        """IMAP is receive-only - cannot send messages."""
        raise NotImplementedError(
            "IMAP is receive-only. Use SMTP platforms for sending messages."
        )

    def reply(self, original_message: Message, content: str, **kwargs) -> Message:
        """IMAP is receive-only - cannot send replies."""
        raise NotImplementedError(
            "IMAP is receive-only. Use SMTP platforms for sending replies."
        )
