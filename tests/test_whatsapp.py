# tests/test_whatsapp.py
"""
Mock-based smoke tests for the WhatsApp adapter. No real WhatsApp/Meta
credentials or network access required - httpx's Client/AsyncClient are
swapped out for small in-memory fakes.

Run with: PYTHONPATH=src python3 -m unittest tests.test_whatsapp -v
"""
import asyncio
import unittest
from unittest.mock import patch

import trivialmessage.whatsapp as whatsapp_mod
from trivialmessage.common import Message


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text or str(self._json)

    def json(self):
        return self._json


class FakeSyncClient:
    response = FakeResponse(json_data={"messages": [{"id": "wamid.123"}]})
    last_call = None

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, json=None, headers=None):
        FakeSyncClient.last_call = {"url": url, "json": json, "headers": headers}
        return FakeSyncClient.response


class FakeAsyncClient:
    response = FakeResponse(json_data={"messages": [{"id": "wamid.456"}]})
    last_call = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None):
        FakeAsyncClient.last_call = {"url": url, "json": json, "headers": headers}
        return FakeAsyncClient.response


class WhatsAppAdapterTests(unittest.TestCase):
    def setUp(self):
        self.platform = whatsapp_mod.WhatsAppPlatform(
            phone_number="1234567890", access_token="fake-token"
        )
        FakeSyncClient.response = FakeResponse(
            json_data={"messages": [{"id": "wamid.123"}]}
        )
        FakeAsyncClient.response = FakeResponse(
            json_data={"messages": [{"id": "wamid.456"}]}
        )

    def test_send(self):
        with patch.object(whatsapp_mod.httpx, "Client", FakeSyncClient):
            msg = self.platform.send("hi there", to="15550001111")

        self.assertIsInstance(msg, Message)
        self.assertEqual(msg.id, "wamid.123")
        self.assertEqual(msg.recipient, "15550001111")
        self.assertEqual(msg.platform_type, "whatsapp")
        self.assertEqual(
            FakeSyncClient.last_call["json"],
            {
                "messaging_product": "whatsapp",
                "to": "15550001111",
                "text": {"body": "hi there"},
            },
        )
        self.assertEqual(
            FakeSyncClient.last_call["headers"]["Authorization"], "Bearer fake-token"
        )

    def test_send_raises_on_http_error(self):
        FakeSyncClient.response = FakeResponse(
            status_code=401, text='{"error": {"message": "Invalid token"}}'
        )
        with patch.object(whatsapp_mod.httpx, "Client", FakeSyncClient):
            with self.assertRaises(RuntimeError):
                self.platform.send("hi", to="15550001111")

    def test_reply_quotes_when_requested(self):
        original = Message(
            id="wamid.orig",
            platform_type="whatsapp",
            content="original text",
            sender="15550002222",
            timestamp=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ),
        )
        with patch.object(whatsapp_mod.httpx, "Client", FakeSyncClient):
            self.platform.reply(original, "a reply", quote_original=True)

        sent_body = FakeSyncClient.last_call["json"]["text"]["body"]
        self.assertIn("original text", sent_body)
        self.assertIn("a reply", sent_body)
        self.assertEqual(FakeSyncClient.last_call["json"]["to"], "15550002222")

    def test_reply_without_sender_raises(self):
        original = Message(
            id="wamid.orig",
            platform_type="whatsapp",
            content="x",
            sender="",
            timestamp=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ),
        )
        with self.assertRaises(ValueError):
            self.platform.reply(original, "reply")

    def test_send_async(self):
        with patch.object(whatsapp_mod.httpx, "AsyncClient", FakeAsyncClient):
            msg = asyncio.run(self.platform.send_async("async hi", to="15550003333"))

        self.assertEqual(msg.id, "wamid.456")
        self.assertEqual(msg.recipient, "15550003333")

    def test_reply_async(self):
        original = Message(
            id="wamid.orig2",
            platform_type="whatsapp",
            content="original",
            sender="15550004444",
            timestamp=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ),
        )
        with patch.object(whatsapp_mod.httpx, "AsyncClient", FakeAsyncClient):
            msg = asyncio.run(self.platform.reply_async(original, "reply async"))

        self.assertEqual(msg.recipient, "15550004444")

    def test_get_unread_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.platform.get_unread()

    def test_get_recent_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.platform.get_recent()

    def test_listen_not_implemented(self):
        async def run():
            with self.assertRaises(NotImplementedError):
                await self.platform.listen().__anext__()

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
