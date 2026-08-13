# src/trivialmessage/twilio.py
"""
Twilio adapter: SMS (full MessagePlatform) + Voice (deliberately partial).

Two separate classes, one shared account:

  TwilioSMSPlatform
    Implements the full MessagePlatform interface. Twilio's Messages
    resource is genuinely queryable (unlike WhatsApp's Cloud API), so
    get_recent works for real; get_unread does not (SMS has no
    read/unread state). Inbound messages arrive via a webhook Twilio
    calls on your number, so `listen()` uses a queue-bridge: your web
    framework hands parsed webhook payloads to `.ingest(...)`, and
    `listen()` drains that queue as an async generator.

  TwilioVoicePlatform
    Deliberately NOT a MessagePlatform - this is a robocall notifier,
    not an inbound call service. It only implements send/send_async/
    reply/reply_async. There is no listen()/get_recent()/get_unread():
    we are not standing up a webhook server to receive inbound calls or
    call-status callbacks here. `content` is an AudioContent (text to
    speak via Twilio's <Say>, or a URL to a hosted audio file to play
    via <Play>) rather than a str.

Both use Twilio's REST API directly over httpx + HTTP Basic Auth
(Account SID / Auth Token) rather than the official `twilio` SDK, to
keep this dependency-light and consistent with the rest of the library
(WhatsApp/Outlook do the same).

IMPORTANT: Twilio's REST API expects x-www-form-urlencoded bodies, not
JSON - that's `data=...`, not `json=...`, in every httpx call below.
"""
import asyncio
import xml.sax.saxutils as saxutils
from dataclasses import dataclass
from datetime import datetime, timezone
from os import environ as ENV
from typing import AsyncIterator, Dict, List, Optional
from urllib.parse import quote as urlquote

import httpx

from .common import Message, MessageFilter, MessagePlatform

TWILIO_API_BASE = "https://api.twilio.com/2010-04-01"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _raise_for_twilio_error(response: httpx.Response) -> None:
    if response.status_code >= 400:
        raise RuntimeError(
            f"Twilio request failed ({response.status_code}): {response.text}"
        )


def _parse_twilio_datetime(value: Optional[str]) -> datetime:
    """Twilio timestamps look like 'Thu, 13 Aug 2026 18:30:00 +0000' (RFC 2822)."""
    if not value:
        return datetime.now(timezone.utc)
    try:
        from email.utils import parsedate_to_datetime

        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# SMS
# ---------------------------------------------------------------------------


class TwilioSMSPlatform(MessagePlatform):
    """SMS implementation using the Twilio Messages REST resource."""

    def __init__(
        self,
        account_sid: str,
        auth_token: str,
        from_number: Optional[str] = None,
        messaging_service_sid: Optional[str] = None,
    ):
        if not from_number and not messaging_service_sid:
            raise ValueError("Must provide either from_number or messaging_service_sid")
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number
        self.messaging_service_sid = messaging_service_sid
        self.base_url = f"{TWILIO_API_BASE}/Accounts/{account_sid}"

        # Webhook -> listen() bridge. See `ingest` / `parse_webhook`.
        self._queue: "asyncio.Queue[Message]" = asyncio.Queue()

    @classmethod
    def from_env(cls) -> "TwilioSMSPlatform":
        return cls(
            account_sid=ENV["TWILIO_ACCOUNT_SID"],
            auth_token=ENV["TWILIO_AUTH_TOKEN"],
            from_number=ENV.get("TWILIO_FROM_NUMBER"),
            messaging_service_sid=ENV.get("TWILIO_MESSAGING_SERVICE_SID"),
        )

    @property
    def _auth(self) -> httpx.BasicAuth:
        return httpx.BasicAuth(self.account_sid, self.auth_token)

    def _send_payload(self, to: str, content: str) -> Dict[str, str]:
        payload = {"To": to, "Body": content}
        if self.messaging_service_sid:
            payload["MessagingServiceSid"] = self.messaging_service_sid
        else:
            payload["From"] = self.from_number
        return payload

    def _result_to_message(self, content: str, to: str, result: dict) -> Message:
        return Message(
            id=result.get("sid", f"sms-{datetime.now(timezone.utc).isoformat()}"),
            platform_type="sms",
            content=content,
            sender=result.get("from") or self.from_number or "",
            timestamp=_parse_twilio_datetime(result.get("date_created")),
            recipient=to,
            raw_data=result,
            platform_metadata={
                "sent": True,
                "status": result.get("status"),
                "sid": result.get("sid"),
            },
        )

    def send(self, content: str, **kwargs) -> Message:
        """Send an SMS message."""
        to = kwargs.get("to")
        if not to:
            raise ValueError("'to' recipient is required")

        with httpx.Client() as client:
            response = client.post(
                f"{self.base_url}/Messages.json",
                data=self._send_payload(to, content),
                auth=self._auth,
            )
            _raise_for_twilio_error(response)
            return self._result_to_message(content, to, response.json())

    async def send_async(self, content: str, **kwargs) -> Message:
        """Send an SMS message using an async HTTP client."""
        to = kwargs.get("to")
        if not to:
            raise ValueError("'to' recipient is required")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/Messages.json",
                data=self._send_payload(to, content),
                auth=self._auth,
            )
            _raise_for_twilio_error(response)
            return self._result_to_message(content, to, response.json())

    def reply(self, original_message: Message, content: str, **kwargs) -> Message:
        """Reply to an SMS message. SMS has no threading, so this just
        sends a fresh message back to the original sender."""
        reply_to = original_message.sender
        if not reply_to:
            raise ValueError("Cannot determine sender from original message")
        return self.send(content=content, to=reply_to)

    async def reply_async(
        self, original_message: Message, content: str, **kwargs
    ) -> Message:
        reply_to = original_message.sender
        if not reply_to:
            raise ValueError("Cannot determine sender from original message")
        return await self.send_async(content=content, to=reply_to)

    def get_recent(
        self,
        limit: int = 10,
        since: Optional[datetime] = None,
        filters: Optional[MessageFilter] = None,
    ) -> List[Message]:
        """
        List recent messages via Twilio's Messages resource. Unlike
        WhatsApp's Cloud API, Twilio genuinely supports querying message
        history, so this is a real implementation, not a stub.
        """
        merged = filters or MessageFilter()
        if since:
            merged.since = since

        params: Dict[str, str] = {"PageSize": str(min(max(int(limit), 1), 1000))}
        if merged.sender:
            params["From"] = merged.sender
        if merged.recipient:
            params["To"] = merged.recipient
        if merged.since:
            params["DateSentAfter"] = merged.since.astimezone(timezone.utc).strftime(
                "%Y-%m-%d"
            )
        if merged.until:
            params["DateSentBefore"] = merged.until.astimezone(timezone.utc).strftime(
                "%Y-%m-%d"
            )

        with httpx.Client() as client:
            response = client.get(
                f"{self.base_url}/Messages.json", params=params, auth=self._auth
            )
            _raise_for_twilio_error(response)
            result = response.json()

        messages = []
        for m in result.get("messages", [])[:limit]:
            msg = Message(
                id=m.get("sid", ""),
                platform_type="sms",
                content=m.get("body", ""),
                sender=m.get("from", ""),
                timestamp=_parse_twilio_datetime(m.get("date_sent")),
                recipient=m.get("to", ""),
                raw_data=m,
                platform_metadata={"status": m.get("status"), "sid": m.get("sid")},
            )
            if msg.matches_filter(merged):
                messages.append(msg)
        return messages

    def get_unread(self, filters: Optional[MessageFilter] = None) -> List[Message]:
        """SMS has no server-side read/unread concept."""
        raise NotImplementedError(
            "SMS has no read/unread state; use get_recent() instead"
        )

    async def listen(
        self, filters: Optional[MessageFilter] = None, mark_read: bool = False
    ) -> AsyncIterator[Message]:
        """
        Drains messages pushed via `ingest()`. Twilio delivers inbound SMS
        by calling a webhook URL you configure on your number - this
        library doesn't run a web server, so wire your framework's
        webhook route to call:

            sms.ingest(TwilioSMSPlatform.parse_webhook(request.form))
        """
        while True:
            message = await self._queue.get()
            if message.matches_filter(filters):
                yield message

    def ingest(self, message: Message) -> None:
        """Feed a parsed inbound message (see `parse_webhook`) into `listen()`."""
        self._queue.put_nowait(message)

    @staticmethod
    def parse_webhook(form_data: Dict[str, str]) -> Message:
        """
        Parse Twilio's inbound-SMS webhook POST body (form-encoded) into a
        Message. Expected fields: From, To, Body, MessageSid,
        (optionally) NumMedia/MediaUrl0 etc for MMS attachments.
        """
        return Message(
            id=form_data.get("MessageSid", ""),
            platform_type="sms",
            content=form_data.get("Body", ""),
            sender=form_data.get("From", ""),
            timestamp=datetime.now(timezone.utc),
            recipient=form_data.get("To", ""),
            raw_data=dict(form_data),
            platform_metadata={"sid": form_data.get("MessageSid"), "inbound": True},
        )


# ---------------------------------------------------------------------------
# Voice (send/reply only - see module docstring)
# ---------------------------------------------------------------------------


@dataclass
class AudioContent:
    """
    What to play/say on a call. Exactly one of `text`/`url` should be set.

      - text: spoken via Twilio's built-in <Say> TTS. No hosting, no
        extra service - this is the recommended default for "notify
        someone of an urgent development" style alerts.
      - url: a publicly reachable audio file Twilio's <Play> verb will
        fetch and play (e.g. pre-recorded/pre-synthesized WAV/MP3
        already hosted somewhere).

    There's deliberately no `wav_bytes` field: Twilio's REST API can't
    accept inline audio bytes for playback (<Play> needs a URL), and
    this adapter isn't in the business of hosting files. If you have raw
    audio, upload it yourself and pass the resulting URL.
    """

    text: Optional[str] = None
    url: Optional[str] = None
    voice: Optional[str] = None  # Twilio <Say> voice, e.g. "Polly.Joanna"

    def __post_init__(self):
        if bool(self.text) == bool(self.url):
            raise ValueError("AudioContent needs exactly one of text or url")


def _build_twiml(content: AudioContent) -> str:
    """Pure function, no I/O - easy to unit test in isolation."""
    if content.url:
        body = f"<Play>{saxutils.escape(content.url)}</Play>"
    else:
        voice_attr = (
            f' voice="{saxutils.escape(content.voice)}"' if content.voice else ""
        )
        body = f"<Say{voice_attr}>{saxutils.escape(content.text)}</Say>"
    return f'<?xml version="1.0" encoding="UTF-8"?><Response>{body}<Hangup/></Response>'


class TwilioVoicePlatform:
    """
    Robocall notifier: places outbound calls that speak/play a message,
    nothing more. Intentionally does not implement listen(), get_recent(),
    or get_unread() - this class does not manage inbound calls, call
    status callbacks, or any webhook-facing surface, and does not
    subclass MessagePlatform (whose ABC would force stub implementations
    of those).
    """

    def __init__(self, account_sid: str, auth_token: str, from_number: str):
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number
        self.base_url = f"{TWILIO_API_BASE}/Accounts/{account_sid}"

    @classmethod
    def from_env(cls) -> "TwilioVoicePlatform":
        return cls(
            account_sid=ENV["TWILIO_ACCOUNT_SID"],
            auth_token=ENV["TWILIO_AUTH_TOKEN"],
            from_number=ENV["TWILIO_VOICE_FROM_NUMBER"],
        )

    @property
    def _auth(self) -> httpx.BasicAuth:
        return httpx.BasicAuth(self.account_sid, self.auth_token)

    def _call_payload(self, to: str, content: AudioContent, **kwargs) -> Dict[str, str]:
        payload = {
            "To": to,
            "From": self.from_number,
            "Twiml": _build_twiml(content),
        }
        if kwargs.get("machine_detection"):
            payload["MachineDetection"] = "Enable"
        return payload

    def _result_to_message(
        self, content: AudioContent, to: str, result: dict
    ) -> Message:
        spoken = content.text or f"[audio: {content.url}]"
        return Message(
            id=result.get("sid", f"call-{datetime.now(timezone.utc).isoformat()}"),
            platform_type="voice",
            content=spoken,
            sender=result.get("from") or self.from_number,
            timestamp=_parse_twilio_datetime(result.get("date_created")),
            recipient=to,
            raw_data=result,
            platform_metadata={
                "sent": True,
                "status": result.get("status"),  # e.g. "queued"
                "sid": result.get("sid"),
                "audio_url": content.url,
            },
        )

    def send(self, content: AudioContent, **kwargs) -> Message:
        """Place an outbound call that speaks/plays `content`, then hangs up."""
        to = kwargs.pop("to", None)
        if not to:
            raise ValueError("'to' recipient is required")

        with httpx.Client() as client:
            response = client.post(
                f"{self.base_url}/Calls.json",
                data=self._call_payload(to, content, **kwargs),
                auth=self._auth,
            )
            _raise_for_twilio_error(response)
            return self._result_to_message(content, to, response.json())

    async def send_async(self, content: AudioContent, **kwargs) -> Message:
        to = kwargs.pop("to", None)
        if not to:
            raise ValueError("'to' recipient is required")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/Calls.json",
                data=self._call_payload(to, content, **kwargs),
                auth=self._auth,
            )
            _raise_for_twilio_error(response)
            return self._result_to_message(content, to, response.json())

    def reply(
        self, original_message: Message, content: AudioContent, **kwargs
    ) -> Message:
        """
        Place a new call back to whoever/whatever `original_message` came
        from (e.g. an SMS asking for a callback, or a prior call-log
        entry). There is no in-call "reply" - this is just `send` aimed
        at `original_message.sender`.
        """
        reply_to = original_message.sender
        if not reply_to:
            raise ValueError("Cannot determine recipient from original message")
        return self.send(content=content, to=reply_to, **kwargs)

    async def reply_async(
        self, original_message: Message, content: AudioContent, **kwargs
    ) -> Message:
        reply_to = original_message.sender
        if not reply_to:
            raise ValueError("Cannot determine recipient from original message")
        return await self.send_async(content=content, to=reply_to, **kwargs)
