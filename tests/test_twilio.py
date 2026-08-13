# tests/test_twilio.py
"""
Tests for the Twilio SMS + Voice adapters. No live Twilio account or
network access - httpx's Client/AsyncClient are swapped for small
in-memory fakes, and TwiML generation is tested as a pure function.

Run with: PYTHONPATH=src python3 -m unittest tests.test_twilio -v
"""
import asyncio
import datetime as dt
import unittest
from unittest.mock import patch

import trivialmessage.twilio as twilio_mod
from trivialmessage.common import Message


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text or str(self._json)

    def json(self):
        return self._json


class FakeSyncClient:
    response = FakeResponse()
    last_call = None

    def __init__(self, *a, **kw):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, data=None, auth=None):
        FakeSyncClient.last_call = {"method": "POST", "url": url, "data": data}
        return FakeSyncClient.response

    def get(self, url, params=None, auth=None):
        FakeSyncClient.last_call = {"method": "GET", "url": url, "params": params}
        return FakeSyncClient.response


class FakeAsyncClient:
    response = FakeResponse()
    last_call = None

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, data=None, auth=None):
        FakeAsyncClient.last_call = {"method": "POST", "url": url, "data": data}
        return FakeAsyncClient.response


# ---------------------------------------------------------------------------
# TwiML generation - pure, no I/O
# ---------------------------------------------------------------------------


class TwiMLTests(unittest.TestCase):
    def test_text_renders_say(self):
        xml = twilio_mod._build_twiml(twilio_mod.AudioContent(text="server is down"))
        self.assertIn("<Say>server is down</Say>", xml)
        self.assertIn("<Hangup/>", xml)

    def test_url_renders_play(self):
        xml = twilio_mod._build_twiml(
            twilio_mod.AudioContent(url="https://example.com/alert.wav")
        )
        self.assertIn("<Play>https://example.com/alert.wav</Play>", xml)

    def test_voice_attribute(self):
        xml = twilio_mod._build_twiml(
            twilio_mod.AudioContent(text="hi", voice="Polly.Joanna")
        )
        self.assertIn('voice="Polly.Joanna"', xml)

    def test_text_is_xml_escaped(self):
        xml = twilio_mod._build_twiml(twilio_mod.AudioContent(text="A & B < C"))
        self.assertIn("A &amp; B &lt; C", xml)
        self.assertNotIn("A & B < C", xml)

    def test_requires_exactly_one_of_text_or_url(self):
        with self.assertRaises(ValueError):
            twilio_mod.AudioContent()
        with self.assertRaises(ValueError):
            twilio_mod.AudioContent(text="hi", url="https://example.com/a.wav")


# ---------------------------------------------------------------------------
# SMS
# ---------------------------------------------------------------------------


class TwilioSMSTests(unittest.TestCase):
    def setUp(self):
        self.platform = twilio_mod.TwilioSMSPlatform(
            account_sid="ACxxxx", auth_token="tok", from_number="+15550001111"
        )
        FakeSyncClient.response = FakeResponse(
            json_data={
                "sid": "SMxxxx",
                "from": "+15550001111",
                "status": "queued",
                "date_created": "Thu, 13 Aug 2026 18:30:00 +0000",
            }
        )
        FakeAsyncClient.response = FakeResponse(
            json_data={
                "sid": "SMyyyy",
                "from": "+15550001111",
                "status": "queued",
                "date_created": "Thu, 13 Aug 2026 18:31:00 +0000",
            }
        )

    def test_requires_from_number_or_messaging_service(self):
        with self.assertRaises(ValueError):
            twilio_mod.TwilioSMSPlatform(account_sid="AC", auth_token="t")

    def test_send_uses_form_encoding_not_json(self):
        with patch.object(twilio_mod.httpx, "Client", FakeSyncClient):
            msg = self.platform.send("hello", to="+15550002222")

        self.assertIsInstance(msg, Message)
        self.assertEqual(msg.id, "SMxxxx")
        self.assertEqual(msg.recipient, "+15550002222")
        self.assertEqual(msg.platform_type, "sms")
        # Twilio wants form data, not JSON
        self.assertEqual(
            FakeSyncClient.last_call["data"],
            {"To": "+15550002222", "Body": "hello", "From": "+15550001111"},
        )

    def test_send_prefers_messaging_service_sid_when_set(self):
        platform = twilio_mod.TwilioSMSPlatform(
            account_sid="ACxxxx", auth_token="tok", messaging_service_sid="MGxxxx"
        )
        with patch.object(twilio_mod.httpx, "Client", FakeSyncClient):
            platform.send("hi", to="+15550002222")

        data = FakeSyncClient.last_call["data"]
        self.assertEqual(data["MessagingServiceSid"], "MGxxxx")
        self.assertNotIn("From", data)

    def test_send_raises_on_http_error(self):
        FakeSyncClient.response = FakeResponse(status_code=400, text="bad request")
        with patch.object(twilio_mod.httpx, "Client", FakeSyncClient):
            with self.assertRaises(RuntimeError):
                self.platform.send("hi", to="+15550002222")

    def test_send_async(self):
        with patch.object(twilio_mod.httpx, "AsyncClient", FakeAsyncClient):
            msg = asyncio.run(self.platform.send_async("hi async", to="+15550003333"))
        self.assertEqual(msg.id, "SMyyyy")

    def test_reply_sends_to_original_sender(self):
        original = Message(
            id="in-1",
            platform_type="sms",
            content="are you up?",
            sender="+15550009999",
            timestamp=dt.datetime.now(dt.timezone.utc),
        )
        with patch.object(twilio_mod.httpx, "Client", FakeSyncClient):
            self.platform.reply(original, "yes, all good")
        self.assertEqual(FakeSyncClient.last_call["data"]["To"], "+15550009999")

    def test_reply_async(self):
        original = Message(
            id="in-2",
            platform_type="sms",
            content="ping",
            sender="+15550008888",
            timestamp=dt.datetime.now(dt.timezone.utc),
        )
        with patch.object(twilio_mod.httpx, "AsyncClient", FakeAsyncClient):
            asyncio.run(self.platform.reply_async(original, "pong"))
        self.assertEqual(FakeAsyncClient.last_call["data"]["To"], "+15550008888")

    def test_get_recent_parses_messages_and_applies_limit(self):
        FakeSyncClient.response = FakeResponse(
            json_data={
                "messages": [
                    {
                        "sid": "SM1",
                        "from": "+15551111111",
                        "to": "+15552222222",
                        "body": "one",
                        "status": "received",
                        "date_sent": "Thu, 13 Aug 2026 10:00:00 +0000",
                    },
                    {
                        "sid": "SM2",
                        "from": "+15551111111",
                        "to": "+15552222222",
                        "body": "two",
                        "status": "received",
                        "date_sent": "Thu, 13 Aug 2026 11:00:00 +0000",
                    },
                ]
            }
        )
        with patch.object(twilio_mod.httpx, "Client", FakeSyncClient):
            msgs = self.platform.get_recent(limit=1)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].content, "one")

    def test_get_unread_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.platform.get_unread()

    def test_listen_drains_ingested_messages(self):
        webhook_payload = {
            "MessageSid": "SMinbound1",
            "From": "+15557777777",
            "To": "+15550001111",
            "Body": "incoming!",
        }
        parsed = twilio_mod.TwilioSMSPlatform.parse_webhook(webhook_payload)
        self.assertEqual(parsed.content, "incoming!")
        self.assertEqual(parsed.sender, "+15557777777")

        async def run():
            self.platform.ingest(parsed)
            msg = await asyncio.wait_for(self.platform.listen().__anext__(), timeout=5)
            self.assertEqual(msg.id, "SMinbound1")

        asyncio.run(run())


# ---------------------------------------------------------------------------
# Voice
# ---------------------------------------------------------------------------


class TwilioVoiceTests(unittest.TestCase):
    def setUp(self):
        self.platform = twilio_mod.TwilioVoicePlatform(
            account_sid="ACxxxx", auth_token="tok", from_number="+15550001111"
        )
        FakeSyncClient.response = FakeResponse(
            json_data={
                "sid": "CAxxxx",
                "from": "+15550001111",
                "status": "queued",
                "date_created": "Thu, 13 Aug 2026 18:30:00 +0000",
            }
        )
        FakeAsyncClient.response = FakeResponse(
            json_data={
                "sid": "CAyyyy",
                "from": "+15550001111",
                "status": "queued",
                "date_created": "Thu, 13 Aug 2026 18:31:00 +0000",
            }
        )

    def test_send_places_call_with_generated_twiml(self):
        with patch.object(twilio_mod.httpx, "Client", FakeSyncClient):
            msg = self.platform.send(
                twilio_mod.AudioContent(text="prod is down"), to="+15559998888"
            )

        self.assertEqual(msg.id, "CAxxxx")
        self.assertEqual(msg.platform_type, "voice")
        self.assertEqual(msg.content, "prod is down")
        sent = FakeSyncClient.last_call["data"]
        self.assertEqual(sent["To"], "+15559998888")
        self.assertIn("<Say>prod is down</Say>", sent["Twiml"])
        self.assertNotIn("MachineDetection", sent)

    def test_send_with_machine_detection_flag(self):
        with patch.object(twilio_mod.httpx, "Client", FakeSyncClient):
            self.platform.send(
                twilio_mod.AudioContent(text="hi"),
                to="+15559998888",
                machine_detection=True,
            )
        self.assertEqual(FakeSyncClient.last_call["data"]["MachineDetection"], "Enable")

    def test_send_requires_to(self):
        with self.assertRaises(ValueError):
            self.platform.send(twilio_mod.AudioContent(text="hi"))

    def test_send_raises_on_http_error(self):
        FakeSyncClient.response = FakeResponse(status_code=500, text="server error")
        with patch.object(twilio_mod.httpx, "Client", FakeSyncClient):
            with self.assertRaises(RuntimeError):
                self.platform.send(twilio_mod.AudioContent(text="hi"), to="+1555")

    def test_send_async(self):
        with patch.object(twilio_mod.httpx, "AsyncClient", FakeAsyncClient):
            msg = asyncio.run(
                self.platform.send_async(
                    twilio_mod.AudioContent(url="https://example.com/a.wav"),
                    to="+15559998888",
                )
            )
        self.assertEqual(msg.id, "CAyyyy")
        self.assertEqual(
            msg.platform_metadata["audio_url"], "https://example.com/a.wav"
        )

    def test_reply_calls_back_original_sender(self):
        original = Message(
            id="log-1",
            platform_type="voice",
            content="missed call",
            sender="+15556665555",
            timestamp=dt.datetime.now(dt.timezone.utc),
        )
        with patch.object(twilio_mod.httpx, "Client", FakeSyncClient):
            self.platform.reply(original, twilio_mod.AudioContent(text="calling back"))
        self.assertEqual(FakeSyncClient.last_call["data"]["To"], "+15556665555")

    def test_reply_async(self):
        original = Message(
            id="log-2",
            platform_type="voice",
            content="missed call",
            sender="+15554443333",
            timestamp=dt.datetime.now(dt.timezone.utc),
        )
        with patch.object(twilio_mod.httpx, "AsyncClient", FakeAsyncClient):
            asyncio.run(
                self.platform.reply_async(original, twilio_mod.AudioContent(text="hi"))
            )
        self.assertEqual(FakeAsyncClient.last_call["data"]["To"], "+15554443333")

    def test_voice_platform_has_no_listen_or_history_methods(self):
        # Deliberately partial per the design - this is not a MessagePlatform.
        self.assertFalse(hasattr(self.platform, "listen"))
        self.assertFalse(hasattr(self.platform, "get_recent"))
        self.assertFalse(hasattr(self.platform, "get_unread"))
        self.assertNotIsInstance(self.platform, twilio_mod.MessagePlatform)


if __name__ == "__main__":
    unittest.main()
