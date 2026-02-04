# src/trivialmessage/protonmail.py
"""
Proton Mail (Bridge) platform implementation.

This platform talks ONLY to a local Proton Mail Bridge instance via IMAP + SMTP.
Bridge commonly uses a self-signed certificate; this module disables TLS
verification for those local connections by default.

Typical env contract (same as the legacy ProtonMailbox):

  - IMAP (receive/fetch/flags)
      BRIDGE_IMAP_USER
      BRIDGE_IMAP_PASSWORD
      BRIDGE_IMAP_HOST        (optional; default 127.0.0.1)
      BRIDGE_IMAP_PORT        (optional; default 1143)
      BRIDGE_IMAP_SECURITY    (optional; default STARTTLS)

  - SMTP (send) - Bridge exposes SMTP locally
      BRIDGE_SMTP_HOST        (optional; default = IMAP host)
      BRIDGE_SMTP_PORT        (optional; default 1025)
      BRIDGE_SMTP_SECURITY    (optional; default STARTTLS)
      BRIDGE_EMAIL_FROM       (optional; default = BRIDGE_IMAP_USER)

Notes:
- Bidirectional: yes (IMAP receive + SMTP send), but both are *Bridge-local*.
- Listening is IDLE + polling fallback behavior (IMAPClient idle_check timeout).
- IMAP "SINCE/BEFORE" are date-granularity; time precision is not available.
"""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email import policy
from email.message import EmailMessage
from email.message import Message as PyEmailMessage
from email.parser import BytesParser
from email.utils import (formatdate, make_msgid, parseaddr,
                         parsedate_to_datetime)
from os import environ as ENV
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple, Union

from imapclient import IMAPClient

from .common import Message, MessageFilter, MessagePlatform

_IMAP_MONTHS = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
]


def _make_ssl_context() -> ssl.SSLContext:
    """
    This service only ever talks to a local Bridge instance.
    Bridge commonly uses a self-signed cert; we disable verification.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _normalize_mode(mode_or_security: Optional[str]) -> str:
    """
    Bridge tends to describe connection security as STARTTLS / SSL / None.
    Map to our internal "STARTTLS" | "SSL" | "PLAINTEXT".
    """
    if not mode_or_security:
        return "STARTTLS"
    m = str(mode_or_security).strip().upper()
    if m in {"SSL", "IMAPS", "SMTPS"}:
        return "SSL"
    if m in {"STARTTLS", "TLS"}:
        return "STARTTLS"
    if m in {"NONE", "PLAINTEXT", "PLAIN", "OFF"}:
        return "PLAINTEXT"
    return "STARTTLS"


def _as_aware_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    try:
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return dt.replace(tzinfo=timezone.utc)


def _parse_date_header_utc(date_header: str) -> Optional[datetime]:
    """
    Best-effort parse of RFC 2822-ish Date header to aware UTC datetime.
    Returns None on failure.
    """
    if not isinstance(date_header, str) or not date_header.strip():
        return None
    try:
        dt = parsedate_to_datetime(date_header.strip())
        return _as_aware_utc(dt)
    except Exception:
        return None


def _imap_date_str(dt: datetime) -> str:
    """IMAP SEARCH date format: 'DD-Mon-YYYY' (day-granularity)."""
    d = dt.day
    m = _IMAP_MONTHS[dt.month - 1] if 1 <= dt.month <= 12 else "Jan"
    y = dt.year
    return f"{d:02d}-{m}-{y:04d}"


def _decode_header_value(val: Optional[str]) -> str:
    # NOTE: Intentionally conservative; does not attempt RFC2047 decoding here.
    return (val or "").strip()


def _extract_bodies(msg: PyEmailMessage) -> Tuple[str, str]:
    """Returns (text_plain, text_html). Either may be ''."""
    text_plain = ""
    text_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue

            ctype = (part.get_content_type() or "").lower()
            disp = (part.get_content_disposition() or "").lower()
            if disp == "attachment":
                continue

            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None

            if not payload:
                continue

            charset = part.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except Exception:
                decoded = payload.decode("utf-8", errors="replace")

            if ctype == "text/plain" and not text_plain:
                text_plain = decoded
            elif ctype == "text/html" and not text_html:
                text_html = decoded
    else:
        ctype = (msg.get_content_type() or "").lower()
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except Exception:
                decoded = payload.decode("utf-8", errors="replace")

            if ctype == "text/html":
                text_html = decoded
            else:
                text_plain = decoded

    return text_plain, text_html


def _parse_emailish(s: str) -> str:
    """Extract address from 'Name <addr>' where possible, else return input."""
    name, addr = parseaddr(s or "")
    return addr.strip() or (s or "").strip()


def _split_addrs(v: Optional[Union[str, List[str]]]) -> List[str]:
    """Accept 'a,b' or ['a','b']; return cleaned list."""
    if not v:
        return []
    if isinstance(v, str):
        parts = [p.strip() for p in v.split(",")]
        return [p for p in parts if p]
    out = []
    for x in v:
        s = str(x or "").strip()
        if s:
            out.append(s)
    return out


@dataclass
class _ConnInfo:
    host: str
    port: int
    mode: str  # "STARTTLS" | "SSL" | "PLAINTEXT"


class ProtonMailPlatform(MessagePlatform):
    """
    Proton Mail Bridge-backed email platform.

    - Receives via IMAP (Bridge-local).
    - Sends via SMTP (Bridge-local).

    This is primarily intended to keep legacy Proton Mail workflows working
    "okay-ish" while newer production flows migrate to Fastmail/JMAP.
    """

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 1143
    DEFAULT_SECURITY = "STARTTLS"
    DEFAULT_FOLDER = "INBOX"

    DEFAULT_SMTP_PORT = 1025
    DEFAULT_SMTP_SECURITY = "STARTTLS"

    def __init__(
        self,
        username: str,
        password: str,
        mode: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        *,
        folder: Optional[str] = None,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_security: Optional[str] = None,
        email_from: Optional[str] = None,
        # Listen behavior knobs
        idle_timeout: int = 60,
        reconnect_backoff_sec: float = 2.0,
        look_back_days: int = 1,
    ):
        self.username = username
        self.password = password

        imap_mode = _normalize_mode(mode or self.DEFAULT_SECURITY)
        imap_host = host or self.DEFAULT_HOST
        imap_port = int(port) if port is not None else self.DEFAULT_PORT

        self._imap = _ConnInfo(host=imap_host, port=imap_port, mode=imap_mode)
        self.folder = folder or self.DEFAULT_FOLDER

        sh = smtp_host or imap_host
        sp = int(smtp_port) if smtp_port is not None else self.DEFAULT_SMTP_PORT
        sm = _normalize_mode(smtp_security or self.DEFAULT_SMTP_SECURITY)
        self._smtp = _ConnInfo(host=sh, port=sp, mode=sm)

        self.email_from = (email_from or username).strip()

        # Listen parameters
        self._idle_timeout = int(idle_timeout) if idle_timeout else 60
        self._reconnect_backoff = (
            float(reconnect_backoff_sec) if reconnect_backoff_sec else 2.0
        )
        self._look_back_days = int(look_back_days) if look_back_days is not None else 1
        if self._look_back_days < 0:
            self._look_back_days = 0

    @classmethod
    def from_env(cls) -> "ProtonMailPlatform":
        username = ENV.get("BRIDGE_IMAP_USER")
        password = ENV.get("BRIDGE_IMAP_PASSWORD")
        if not username or not password:
            raise RuntimeError(
                "Missing Bridge IMAP credentials. Expected BRIDGE_IMAP_USER and BRIDGE_IMAP_PASSWORD."
            )

        host = ENV.get("BRIDGE_IMAP_HOST") or cls.DEFAULT_HOST

        port_s = ENV.get("BRIDGE_IMAP_PORT")
        port = int(port_s) if port_s else cls.DEFAULT_PORT

        security = ENV.get("BRIDGE_IMAP_SECURITY") or cls.DEFAULT_SECURITY

        smtp_host = ENV.get("BRIDGE_SMTP_HOST") or host
        smtp_port_s = ENV.get("BRIDGE_SMTP_PORT")
        smtp_port = int(smtp_port_s) if smtp_port_s else cls.DEFAULT_SMTP_PORT
        smtp_security = ENV.get("BRIDGE_SMTP_SECURITY") or cls.DEFAULT_SMTP_SECURITY

        email_from = (ENV.get("BRIDGE_EMAIL_FROM") or username).strip()

        return cls(
            username=username,
            password=password,
            host=host,
            port=port,
            mode=security,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_security=smtp_security,
            email_from=email_from,
        )

    # -------------------------------------------------------------------------
    # IMAP plumbing
    # -------------------------------------------------------------------------

    def _connect_imap(self) -> IMAPClient:
        ctx = _make_ssl_context()

        if self._imap.mode == "SSL":
            client = IMAPClient(
                self._imap.host, port=self._imap.port, ssl=True, ssl_context=ctx
            )
        else:
            client = IMAPClient(self._imap.host, port=self._imap.port, ssl=False)
            if self._imap.mode == "STARTTLS":
                client.starttls(ssl_context=ctx)

        client.login(self.username, self.password)
        return client

    def _build_search_criteria(
        self,
        base: List[Any],
        filters: Optional[MessageFilter],
    ) -> List[Any]:
        """
        IMAPClient search criteria builder.

        Note: IMAP search is not consistent across servers; we keep this conservative.
        Any additional filtering happens post-fetch via Message.matches_filter.
        """
        criteria: List[Any] = list(base or [])

        if not filters:
            return criteria

        if filters.sender:
            criteria.extend(["FROM", str(filters.sender)])
        if filters.recipient:
            criteria.extend(["TO", str(filters.recipient)])
        if filters.subject_contains:
            criteria.extend(["SUBJECT", str(filters.subject_contains)])
        if filters.content_contains:
            # TEXT searches headers + body; usually closer to what user expects.
            criteria.extend(["TEXT", str(filters.content_contains)])

        if filters.since:
            since_utc = _as_aware_utc(filters.since) or datetime.now(timezone.utc)
            criteria.extend(["SINCE", _imap_date_str(since_utc)])
        if filters.until:
            until_utc = _as_aware_utc(filters.until) or datetime.now(timezone.utc)
            criteria.extend(["BEFORE", _imap_date_str(until_utc)])

        return criteria

    def _fetch_messages(
        self,
        search_criteria: List[Any],
        *,
        peek: bool = True,
        limit: Optional[int] = None,
    ) -> List[Message]:
        """
        Fetch messages matching IMAP search criteria, converting to Message objects.

        peek=True uses BODY.PEEK[] to avoid side-effecting \\Seen.
        """
        with self._connect_imap() as c:
            c.select_folder(self.folder, readonly=peek)

            uids = c.search(search_criteria)
            if not uids:
                return []

            # IMAP SEARCH returns ascending uids; keep only newest tail if limiting.
            if limit is not None and limit > 0 and len(uids) > limit:
                uids = uids[-limit:]

            body_item = "BODY.PEEK[]" if peek else "RFC822"
            fetched = c.fetch(uids, [body_item, "FLAGS", "INTERNALDATE"])

            out: List[Message] = []
            for uid in sorted(fetched.keys()):
                data = fetched[uid]

                # BODY.PEEK[] usually comes back keyed as BODY[] (not BODY.PEEK[])
                rfc822 = (
                    data.get(b"RFC822")
                    or data.get("RFC822")
                    or data.get(b"BODY[]")
                    or data.get("BODY[]")
                )
                if not isinstance(rfc822, (bytes, bytearray)):
                    continue

                internaldate = data.get(b"INTERNALDATE") or data.get("INTERNALDATE")
                idt = internaldate if isinstance(internaldate, datetime) else None

                flags = data.get(b"FLAGS") or data.get("FLAGS")
                msg_obj = self._rfc822_to_message(
                    int(uid), bytes(rfc822), flags=flags, internaldate=idt
                )
                out.append(msg_obj)

            # Most callers want recent-first ordering
            out.sort(key=lambda m: m.timestamp, reverse=True)
            return out

    def _rfc822_to_message(
        self,
        uid: int,
        rfc822: bytes,
        *,
        flags: Optional[Tuple[bytes, ...]] = None,
        internaldate: Optional[datetime] = None,
    ) -> Message:
        msg = BytesParser(policy=policy.default).parsebytes(rfc822)
        text_plain, text_html = _extract_bodies(msg)

        # Flags normalization
        norm_flags: List[str] = []
        if flags:
            for f in flags:
                try:
                    norm_flags.append(f.decode("utf-8", errors="replace"))
                except Exception:
                    norm_flags.append(str(f))

        # Timestamp: prefer INTERNALDATE, else Date header, else now.
        ts = _as_aware_utc(internaldate)
        if ts is None:
            ts = _parse_date_header_utc(_decode_header_value(msg.get("Date")))  # type: ignore[arg-type]
        if ts is None:
            ts = datetime.now(timezone.utc)

        sender = _decode_header_value(msg.get("From"))  # type: ignore[arg-type]
        recipient = _decode_header_value(msg.get("To"))  # type: ignore[arg-type]
        subject = _decode_header_value(msg.get("Subject"))  # type: ignore[arg-type]
        message_id = _decode_header_value(msg.get("Message-ID"))  # type: ignore[arg-type]
        in_reply_to = _decode_header_value(msg.get("In-Reply-To"))  # type: ignore[arg-type]

        # Prefer plain text content; fall back to HTML if that's all we have.
        content = text_plain or text_html or ""

        # Keep headers JSON-friendly
        raw_headers = {k: str(v) for (k, v) in msg.items()}

        return Message(
            id=str(uid),
            platform_type="protonmail",
            content=content,
            sender=sender,
            timestamp=ts,
            recipient=recipient or None,
            subject=subject or None,
            in_reply_to=in_reply_to or None,
            html_content=text_html if text_html and text_html != text_plain else None,
            raw_data=None,  # avoid embedding full RFC822; use metadata instead
            platform_metadata={
                "uid": uid,
                "message_id": message_id,
                "flags": norm_flags,
                "internaldate": (
                    _as_aware_utc(internaldate).isoformat() if internaldate else ""
                ),
                "raw_headers": raw_headers,
                "from_addr": _parse_emailish(sender),
                "to_addr": _parse_emailish(recipient),
            },
        )

    def _mark_seen_uids(self, uids: List[int]) -> bool:
        if not uids:
            return False
        try:
            with self._connect_imap() as c:
                c.select_folder(self.folder)
                c.add_flags(uids, [b"\\Seen"])
            return True
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # SMTP plumbing
    # -------------------------------------------------------------------------

    def _smtp_send(self, msg: EmailMessage, rcpt_addrs: List[str]) -> None:
        ctx = _make_ssl_context()

        if self._smtp.mode == "SSL":
            s: Union[smtplib.SMTP, smtplib.SMTP_SSL] = smtplib.SMTP_SSL(
                self._smtp.host, self._smtp.port, context=ctx, timeout=15
            )
        else:
            s = smtplib.SMTP(self._smtp.host, self._smtp.port, timeout=15)

        try:
            s.ehlo()
            if self._smtp.mode == "STARTTLS":
                s.starttls(context=ctx)
                s.ehlo()

            # Bridge expects the same credentials as IMAP.
            s.login(self.username, self.password)

            # Explicit from/to for clarity
            s.send_message(msg, from_addr=self.email_from, to_addrs=rcpt_addrs)
        finally:
            try:
                s.quit()
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # MessagePlatform API
    # -------------------------------------------------------------------------

    def get_unread(self, filters: Optional[MessageFilter] = None) -> List[Message]:
        criteria = self._build_search_criteria(["UNSEEN"], filters)
        msgs = self._fetch_messages(criteria, peek=True, limit=None)
        return [m for m in msgs if m.matches_filter(filters)]

    def get_recent(
        self,
        limit: int = 10,
        since: Optional[datetime] = None,
        filters: Optional[MessageFilter] = None,
    ) -> List[Message]:
        merged = filters or MessageFilter()
        if since:
            merged.since = since  # common.py will normalize when matching; IMAP needs day-granularity anyway.

        criteria = self._build_search_criteria(["ALL"], merged)
        msgs = self._fetch_messages(criteria, peek=True, limit=max(int(limit), 1))
        return [m for m in msgs if m.matches_filter(merged)][: max(int(limit), 1)]

    async def listen(
        self, filters: Optional[MessageFilter] = None, mark_read: bool = False
    ) -> AsyncIterator[Message]:
        """
        Async generator yielding *new* messages as they arrive.

        Strategy:
          - On each (re)connect, optionally "look back" a small number of days for UNSEEN
            (day granularity), yielding those first.
          - Then use IDLE and yield messages with UID >= baseline uidnext.

        We fetch with BODY.PEEK[] to avoid setting \\Seen by reading the body.
        If mark_read=True, we explicitly add \\Seen after yielding.
        """
        idle_timeout = self._idle_timeout
        reconnect_backoff_sec = self._reconnect_backoff
        look_back_days = self._look_back_days

        backoff = reconnect_backoff_sec

        def _get_rfc822_from_fetch(data: Dict[Any, Any]) -> Optional[bytes]:
            # With BODY.PEEK[] request, IMAP commonly returns the payload under BODY[].
            b = (
                data.get(b"BODY[]")
                or data.get("BODY[]")
                or data.get(b"RFC822")
                or data.get("RFC822")
            )
            return bytes(b) if isinstance(b, (bytes, bytearray)) else None

        while True:
            try:
                with self._connect_imap() as c:
                    c.select_folder(self.folder, readonly=(not mark_read))

                    status = c.folder_status(self.folder, ["UIDNEXT"])
                    uidnext = int(status.get(b"UIDNEXT") or status.get("UIDNEXT") or 1)

                    # --- Look-back: yield recent UNSEEN (bounded) ---
                    if look_back_days > 0:
                        cutoff = datetime.now(timezone.utc) - timedelta(
                            days=look_back_days
                        )
                        since_str = _imap_date_str(cutoff)

                        try:
                            uids_lb = c.search(["UNSEEN", "SINCE", since_str])
                            if uids_lb:
                                fetched_lb = c.fetch(
                                    uids_lb, ["BODY.PEEK[]", "FLAGS", "INTERNALDATE"]
                                )
                                for uid in sorted(fetched_lb.keys()):
                                    data = fetched_lb[uid]
                                    rfc822 = _get_rfc822_from_fetch(data)
                                    if not rfc822:
                                        continue

                                    internaldate = data.get(
                                        b"INTERNALDATE"
                                    ) or data.get("INTERNALDATE")
                                    idt = (
                                        internaldate
                                        if isinstance(internaldate, datetime)
                                        else None
                                    )
                                    flags = data.get(b"FLAGS") or data.get("FLAGS")

                                    msg_obj = self._rfc822_to_message(
                                        int(uid), rfc822, flags=flags, internaldate=idt
                                    )
                                    if msg_obj.matches_filter(filters):
                                        yield msg_obj
                                        if mark_read:
                                            try:
                                                c.add_flags([uid], [b"\\Seen"])
                                            except Exception:
                                                pass
                        except Exception:
                            # Best-effort only; reconnect loop will keep things alive.
                            pass

                    # --- Main IDLE loop for new mail ---
                    while True:
                        c.idle()
                        try:
                            changes = await asyncio.to_thread(
                                c.idle_check, timeout=idle_timeout
                            )
                        finally:
                            try:
                                c.idle_done()
                            except Exception:
                                pass

                        if not changes:
                            continue

                        # Fetch messages from baseline uidnext forward
                        uids = c.search(["UID", f"{uidnext}:*"])
                        if not uids:
                            continue

                        fetched = c.fetch(
                            uids, ["BODY.PEEK[]", "FLAGS", "INTERNALDATE"]
                        )
                        for uid in sorted(fetched.keys()):
                            data = fetched[uid]
                            rfc822 = _get_rfc822_from_fetch(data)
                            if not rfc822:
                                continue

                            internaldate = data.get(b"INTERNALDATE") or data.get(
                                "INTERNALDATE"
                            )
                            idt = (
                                internaldate
                                if isinstance(internaldate, datetime)
                                else None
                            )
                            flags = data.get(b"FLAGS") or data.get("FLAGS")

                            msg_obj = self._rfc822_to_message(
                                int(uid), rfc822, flags=flags, internaldate=idt
                            )
                            if msg_obj.matches_filter(filters):
                                yield msg_obj
                                if mark_read:
                                    try:
                                        c.add_flags([uid], [b"\\Seen"])
                                    except Exception:
                                        pass

                        uidnext = max(int(u) for u in uids) + 1

                backoff = reconnect_backoff_sec

            except asyncio.CancelledError:
                raise
            except GeneratorExit:
                return
            except Exception:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2.0, 60.0)

    def send(self, content: str, **kwargs) -> Message:
        """
        Send an email via Proton Mail Bridge SMTP.

        kwargs:
          - to: str | list[str]   (required)
          - subject: str
          - html: str | None
          - cc: str | list[str] | None
          - bcc: str | list[str] | None
          - from_email: str | None  (optional override for From header; defaults to self.email_from)

        Returns a Message representing the sent email (synthetic id if necessary).
        """
        to_list = _split_addrs(kwargs.get("to"))
        cc_list = _split_addrs(kwargs.get("cc"))
        bcc_list = _split_addrs(kwargs.get("bcc"))
        subject = str(kwargs.get("subject", "") or "")
        html = kwargs.get("html")

        if not (to_list or cc_list or bcc_list):
            raise ValueError("send() requires at least one recipient in to/cc/bcc")

        from_email = (
            str(kwargs.get("from_email") or self.email_from).strip() or self.email_from
        )

        msg = EmailMessage()
        msg["From"] = from_email
        if to_list:
            msg["To"] = ", ".join(to_list)
        if cc_list:
            msg["Cc"] = ", ".join(cc_list)
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid()

        msg.set_content(content or "")
        if html:
            msg.add_alternative(str(html), subtype="html")

        rcpt_addrs = to_list + cc_list + bcc_list
        self._smtp_send(msg, rcpt_addrs)

        mid = _decode_header_value(str(msg.get("Message-ID")))
        ts = datetime.now(timezone.utc)

        return Message(
            id=mid or f"protonmail-sent-{ts.isoformat()}",
            platform_type="protonmail",
            content=content or "",
            sender=from_email,
            timestamp=ts,
            recipient=", ".join(to_list) if to_list else None,
            subject=subject or None,
            html_content=str(html) if html else None,
            raw_data=None,
            platform_metadata={
                "sent": True,
                "message_id": mid,
                "to": to_list,
                "cc": cc_list,
                "bcc": bcc_list,
                "smtp_host": self._smtp.host,
                "smtp_port": self._smtp.port,
                "smtp_security": self._smtp.mode,
            },
        )

    def reply(self, original_message: Message, content: str, **kwargs) -> Message:
        """
        Reply via SMTP (Bridge-local). Threading is best-effort via headers.

        kwargs:
          - quote_original: bool
          - html: str | None
          - cc/bcc/from_email/subject override supported like send()
        """
        reply_to_raw = original_message.sender or ""
        reply_to = _parse_emailish(reply_to_raw) or reply_to_raw
        if not reply_to:
            raise ValueError("Cannot determine reply address from original message")

        original_subject = original_message.subject or ""
        if original_subject and not original_subject.lower().startswith("re:"):
            reply_subject = f"Re: {original_subject}"
        else:
            reply_subject = original_subject

        # Allow explicit override
        if kwargs.get("subject") is not None:
            reply_subject = str(kwargs.get("subject") or "")

        quote_original = bool(kwargs.get("quote_original", False))
        reply_content = content or ""

        if quote_original:
            original_text = original_message.content or ""
            original_date = (
                _as_aware_utc(original_message.timestamp) or datetime.now(timezone.utc)
            ).strftime("%Y-%m-%d %H:%M:%S %Z")
            original_from = original_message.sender or ""
            quoted_text = f"\n\nOn {original_date}, {original_from} wrote:\n"
            quoted_text += "\n".join(f"> {line}" for line in original_text.split("\n"))
            reply_content += quoted_text

        # Build EmailMessage so we can set reply headers.
        from_email = (
            str(kwargs.get("from_email") or self.email_from).strip() or self.email_from
        )
        cc_list = _split_addrs(kwargs.get("cc"))
        bcc_list = _split_addrs(kwargs.get("bcc"))
        html = kwargs.get("html")

        msg = EmailMessage()
        msg["From"] = from_email
        msg["To"] = reply_to
        if cc_list:
            msg["Cc"] = ", ".join(cc_list)
        msg["Subject"] = reply_subject
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid()

        # Threading-ish headers when possible
        if original_message.in_reply_to:
            msg["In-Reply-To"] = original_message.in_reply_to

        # Content
        msg.set_content(reply_content)
        if html:
            msg.add_alternative(str(html), subtype="html")

        rcpt_addrs = [reply_to] + cc_list + bcc_list
        self._smtp_send(msg, rcpt_addrs)

        mid = _decode_header_value(str(msg.get("Message-ID")))
        ts = datetime.now(timezone.utc)

        return Message(
            id=mid or f"protonmail-reply-{ts.isoformat()}",
            platform_type="protonmail",
            content=reply_content,
            sender=from_email,
            timestamp=ts,
            recipient=reply_to,
            subject=reply_subject or None,
            in_reply_to=original_message.in_reply_to,
            html_content=str(html) if html else None,
            raw_data=None,
            platform_metadata={
                "sent": True,
                "is_reply": True,
                "message_id": mid,
                "original_message_id": original_message.id,
                "cc": cc_list,
                "bcc": bcc_list,
                "smtp_host": self._smtp.host,
                "smtp_port": self._smtp.port,
                "smtp_security": self._smtp.mode,
            },
        )
