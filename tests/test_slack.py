# tests/test_slack.py
"""
Mock-based smoke tests for the Slack adapter. No real Slack credentials or
network access required - the Slack SDK clients are swapped for
unittest.mock objects, and the Socket Mode client is swapped for a small
fake that mimics just enough of its interface to exercise `listen()`.

Run with: PYTHONPATH=src python3 -m unittest tests.test_slack -v
"""
import asyncio
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import trivialmessage.slack as slack_mod
from trivialmessage.common import Message, MessageFilter


class FakeSocketModeRequest:
    """Stand-in for slack_sdk.socket_mode.request.SocketModeRequest."""

    def __init__(self, type_, payload, envelope_id="env-1"):
        self.type = type_
        self.payload = payload
        self.envelope_id = envelope_id


class FakeAsyncSocketModeClient:
    """
    Stand-in for the real (aiohttp-based) AsyncSocketModeClient.

    Records itself as `last_instance` so tests can reach in and fire a
    simulated event through whatever listener SlackPlatform.listen()
    registered.
    """

    last_instance = None

    def __init__(self, app_token, web_client):
        self.app_token = app_token
        self.web_client = web_client
        self.socket_mode_request_listeners = []
        self.connected = False
        self.disconnected = False
        self.send_socket_mode_response = AsyncMock()
        FakeAsyncSocketModeClient.last_instance = self

    async def connect(self):
        self.connected = True

    async def disconnect(self):
        self.disconnected = True


class SlackAdapterTests(unittest.TestCase):
    def setUp(self):
        self.platform = slack_mod.SlackPlatform(
            bot_token="xoxb-fake", app_token="xapp-fake"
        )
        # Swap the real Slack web clients for mocks - no network calls.
        self.platform.client = MagicMock()
        self.platform.async_client = MagicMock()

    def test_send(self):
        self.platform.client.chat_postMessage.return_value = {
            "ts": "1699999999.000100",
            "channel": "C123",
        }
        msg = self.platform.send("hello", channel="C123")

        self.assertIsInstance(msg, Message)
        self.assertEqual(msg.recipient, "C123")
        self.assertEqual(msg.content, "hello")
        self.assertEqual(msg.platform_type, "slack")
        self.platform.client.chat_postMessage.assert_called_once_with(
            channel="C123", text="hello", thread_ts=None
        )

    def test_reply_threads_and_mentions_sender(self):
        self.platform.client.chat_postMessage.return_value = {
            "ts": "1700000001.000200",
            "channel": "C123",
        }
        original = Message(
            id="1699999999.000100",
            platform_type="slack",
            content="hi",
            sender="U999",
            timestamp=datetime.now(timezone.utc),
            recipient="C123",
        )

        self.platform.reply(original, "yo")

        kwargs = self.platform.client.chat_postMessage.call_args.kwargs
        self.assertIn("<@U999>", kwargs["text"])
        # Should thread onto the original message's ts since it wasn't
        # already part of a thread.
        self.assertEqual(kwargs["thread_ts"], "1699999999.000100")

    def test_reply_without_channel_raises(self):
        original = Message(
            id="x",
            platform_type="slack",
            content="hi",
            sender="U999",
            timestamp=datetime.now(timezone.utc),
            recipient=None,
        )
        with self.assertRaises(ValueError):
            self.platform.reply(original, "yo")

    def test_send_async(self):
        self.platform.async_client.chat_postMessage = AsyncMock(
            return_value={"ts": "1700000002.000300", "channel": "C456"}
        )
        msg = asyncio.run(self.platform.send_async("async hi", channel="C456"))

        self.assertEqual(msg.recipient, "C456")
        self.assertEqual(msg.content, "async hi")
        self.platform.async_client.chat_postMessage.assert_awaited_once_with(
            channel="C456", text="async hi", thread_ts=None
        )

    def test_reply_async(self):
        self.platform.async_client.chat_postMessage = AsyncMock(
            return_value={"ts": "1700000006.000700", "channel": "C123"}
        )
        original = Message(
            id="1699999999.000100",
            platform_type="slack",
            content="hi",
            sender="U999",
            timestamp=datetime.now(timezone.utc),
            recipient="C123",
        )
        msg = asyncio.run(self.platform.reply_async(original, "yo"))
        self.assertIn("<@U999>", msg.content)

    def test_get_recent_with_channel_filter(self):
        self.platform.client.conversations_history.return_value = {
            "messages": [
                {
                    "ts": "1700000003.000400",
                    "text": "recent 1",
                    "user": "U1",
                    "channel": "C1",
                },
            ]
        }
        msgs = self.platform.get_recent(limit=5, filters=MessageFilter(recipient="C1"))

        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].content, "recent 1")
        self.platform.client.conversations_history.assert_called_once_with(
            channel="C1", limit=5, oldest=None
        )

    def test_get_unread_iterates_channels(self):
        self.platform.client.conversations_list.return_value = {
            "channels": [{"id": "C1", "name": "general"}]
        }
        self.platform.client.conversations_history.return_value = {
            "messages": [
                {
                    "ts": "1700000004.000500",
                    "text": "unread 1",
                    "user": "U1",
                    "channel": "C1",
                },
            ]
        }
        msgs = self.platform.get_unread()

        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].platform_metadata["channel_name"], "general")

    def test_get_unread_skips_inaccessible_channels(self):
        self.platform.client.conversations_list.return_value = {
            "channels": [{"id": "C1", "name": "no-access"}]
        }
        self.platform.client.conversations_history.side_effect = Exception(
            "not_in_channel"
        )

        msgs = self.platform.get_unread()
        self.assertEqual(msgs, [])

    def test_listen_yields_live_messages_and_acks(self):
        """
        Exercises the fixed listen() implementation end to end: registers
        the handler on a fake socket client, fires a simulated event
        through it, and confirms the message comes out the async
        generator - and that the event got acknowledged.
        """
        with patch.object(
            slack_mod, "AsyncSocketModeClient", FakeAsyncSocketModeClient
        ):

            async def run():
                gen = self.platform.listen()
                next_task = asyncio.ensure_future(gen.__anext__())
                await asyncio.sleep(0)  # let listen() reach `await connect()`

                fake_client = FakeAsyncSocketModeClient.last_instance
                self.assertTrue(fake_client.connected)
                self.assertEqual(len(fake_client.socket_mode_request_listeners), 1)

                listener = fake_client.socket_mode_request_listeners[0]
                req = FakeSocketModeRequest(
                    type_="events_api",
                    payload={
                        "event": {
                            "type": "message",
                            "text": "live!",
                            "user": "U1",
                            "channel": "C1",
                            "ts": "1700000005.000600",
                        }
                    },
                )
                await listener(fake_client, req)
                fake_client.send_socket_mode_response.assert_awaited_once()

                msg = await next_task
                self.assertEqual(msg.content, "live!")

                await gen.aclose()
                self.assertTrue(fake_client.disconnected)

            asyncio.run(run())

    def test_listen_without_app_token_raises(self):
        platform = slack_mod.SlackPlatform(bot_token="xoxb-fake")

        async def run():
            with self.assertRaises(ValueError):
                await platform.listen().__anext__()

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
