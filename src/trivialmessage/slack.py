# src/trivialmessage/slack.py
# WIP - this is a work in progress module,
# needs more testing work before we rely on it in prod
#
# NOTE (previously FIXME): `listen` used to import `AsyncSocketModeClient`
# from `slack_sdk.socket_mode.async_client`, which only exposes the abstract
# `AsyncBaseSocketModeClient` - the concrete implementation lives in
# `slack_sdk.socket_mode.aiohttp` and requires the `aiohttp` extra. On top of
# that, the message handler was written as an async *generator* (it used
# `yield`), but slack_sdk's socket mode listeners only ever `await` the
# handler - they never iterate it - so no message was ever making it back to
# the caller, and events were never being acknowledged (which makes Slack
# redeliver them). Both are fixed below using an asyncio.Queue bridge.
import asyncio
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Dict, List, Optional

from slack_sdk.socket_mode.aiohttp import \
    SocketModeClient as AsyncSocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.web.client import WebClient

from .common import Message, MessageFilter, MessagePlatform


class SlackPlatform(MessagePlatform):
    """Slack implementation"""

    def __init__(self, bot_token: str, app_token: Optional[str] = None):
        self.client = WebClient(token=bot_token)
        self.async_client = AsyncWebClient(token=bot_token)
        self._app_token = app_token  # Needed for socket mode

    def _convert_slack_message(
        self, raw_msg: Dict, channel_name: str = None
    ) -> Message:
        """Convert Slack message to Message object"""
        # Parse timestamp
        timestamp = datetime.now(timezone.utc)
        if raw_msg.get("ts"):
            try:
                timestamp = datetime.fromtimestamp(float(raw_msg["ts"]))
            except:
                pass

        return Message(
            id=raw_msg.get("ts", str(raw_msg.get("client_msg_id", ""))),
            platform_type="slack",
            content=raw_msg.get("text", ""),
            sender=raw_msg.get("user", ""),
            timestamp=timestamp,
            recipient=raw_msg.get("channel"),
            thread_id=raw_msg.get("thread_ts"),
            raw_data=raw_msg,
            platform_metadata={
                "channel_name": channel_name or raw_msg.get("channel_name"),
                "subtype": raw_msg.get("subtype"),
                "bot_id": raw_msg.get("bot_id"),
                "team": raw_msg.get("team"),
            },
        )

    def get_unread(self, filters: Optional[MessageFilter] = None) -> List[Message]:
        """Get recent messages from channels (Slack doesn't have 'unread' for bots)"""
        channels = self.client.conversations_list(
            types="public_channel,private_channel,im,mpim"
        )

        all_messages = []
        for channel in channels["channels"]:
            try:
                # Get recent messages (last 24h by default)
                since = (
                    filters.since
                    if filters and filters.since
                    else datetime.now(timezone.utc) - timedelta(days=1)
                )
                oldest = since.timestamp()

                history = self.client.conversations_history(
                    channel=channel["id"], oldest=oldest
                )

                for msg in history["messages"]:
                    # Convert to Message object and apply filters
                    message = self._convert_slack_message(
                        msg, channel.get("name", channel["id"])
                    )
                    if message.matches_filter(filters):
                        all_messages.append(message)

            except Exception:
                # Skip channels we can't access
                continue

        return all_messages

    def get_recent(
        self,
        limit: int = 10,
        since: Optional[datetime] = None,
        filters: Optional[MessageFilter] = None,
    ) -> List[Message]:
        """Get recent messages synchronously"""
        # For Slack, we need to specify channel(s)
        channel_id = filters.recipient if filters else None

        if not channel_id:
            # If no channel specified, get from all channels (expensive!)
            return self.get_unread(filters)[:limit]

        oldest = since.timestamp() if since else None

        history = self.client.conversations_history(
            channel=channel_id, limit=limit, oldest=oldest
        )

        messages = []
        for msg in history["messages"]:
            message = self._convert_slack_message(msg)
            if message.matches_filter(filters):
                messages.append(message)

        return messages[:limit]

    async def listen(
        self, filters: Optional[MessageFilter] = None, mark_read: bool = False
    ) -> AsyncIterator[Message]:
        """Listen for real-time messages using Socket Mode"""
        if not self._app_token:
            raise ValueError("App token required for real-time listening")

        socket_client = AsyncSocketModeClient(
            app_token=self._app_token, web_client=self.async_client
        )

        # Bridge slack_sdk's callback-based listener API to an async
        # generator: the handler pushes onto a queue, and we drain the
        # queue below. This is what actually makes messages reach the
        # caller (see module docstring for why the old approach didn't).
        queue: "asyncio.Queue[Message]" = asyncio.Queue()

        async def message_handler(client, req: SocketModeRequest) -> None:
            # Ack immediately, or Slack will retry-deliver the event.
            await client.send_socket_mode_response(
                SocketModeResponse(envelope_id=req.envelope_id)
            )
            if req.type == "events_api":
                event = req.payload.get("event", {})
                if event.get("type") == "message":
                    message = self._convert_slack_message(event)
                    if message.matches_filter(filters):
                        await queue.put(message)

        socket_client.socket_mode_request_listeners.append(message_handler)
        await socket_client.connect()

        try:
            while True:
                message = await queue.get()
                yield message
        finally:
            await socket_client.disconnect()

    def send(self, content: str, **kwargs) -> Message:
        """Send Slack message"""
        channel = kwargs.get("channel") or kwargs.get("to")
        thread_ts = kwargs.get("thread_ts")

        response = self.client.chat_postMessage(
            channel=channel, text=content, thread_ts=thread_ts
        )

        return Message(
            id=response["ts"],
            platform_type="slack",
            content=content,
            sender="me",  # Sent by bot
            timestamp=datetime.fromtimestamp(float(response["ts"])),
            recipient=channel,
            thread_id=thread_ts,
            raw_data=response,
            platform_metadata={"channel": response["channel"], "sent": True},
        )

    def reply(self, original_message: Message, content: str, **kwargs) -> Message:
        """Reply to a Slack message"""

        # Extract channel from original message
        channel = original_message.recipient
        if not channel:
            raise ValueError("Cannot determine channel from original message")

        # Determine if this should be a threaded reply
        thread_reply = kwargs.get("thread_reply", True)  # Default to threading
        mention_sender = kwargs.get("mention_sender", True)  # Default to mentioning

        reply_content = content

        # Add mention if requested
        if mention_sender and original_message.sender:
            reply_content = f"<@{original_message.sender}> {content}"

        # Determine thread timestamp
        thread_ts = None
        if thread_reply:
            # If original message is already in a thread, reply to that thread
            thread_ts = original_message.thread_id or original_message.id

        return self.send(content=reply_content, channel=channel, thread_ts=thread_ts)

    async def send_async(self, content: str, **kwargs) -> Message:
        """Send a Slack message using the async web client"""
        channel = kwargs.get("channel") or kwargs.get("to")
        thread_ts = kwargs.get("thread_ts")

        response = await self.async_client.chat_postMessage(
            channel=channel, text=content, thread_ts=thread_ts
        )

        return Message(
            id=response["ts"],
            platform_type="slack",
            content=content,
            sender="me",
            timestamp=datetime.fromtimestamp(float(response["ts"])),
            recipient=channel,
            thread_id=thread_ts,
            raw_data=response,
            platform_metadata={"channel": response["channel"], "sent": True},
        )

    async def reply_async(
        self, original_message: Message, content: str, **kwargs
    ) -> Message:
        """Reply to a Slack message using the async web client"""
        channel = original_message.recipient
        if not channel:
            raise ValueError("Cannot determine channel from original message")

        thread_reply = kwargs.get("thread_reply", True)
        mention_sender = kwargs.get("mention_sender", True)

        reply_content = content
        if mention_sender and original_message.sender:
            reply_content = f"<@{original_message.sender}> {content}"

        thread_ts = None
        if thread_reply:
            thread_ts = original_message.thread_id or original_message.id

        return await self.send_async(
            content=reply_content, channel=channel, thread_ts=thread_ts
        )
