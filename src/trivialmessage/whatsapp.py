# src/trivialmessage/whatsapp.py
# WIP - this is a work in progress module,
# needs more testing work before we rely on it in prod
from datetime import datetime, timezone
from typing import AsyncIterator, List, Optional

import httpx

from .common import Message, MessageFilter, MessagePlatform


class WhatsAppPlatform(MessagePlatform):
    """WhatsApp Business API implementation"""

    def __init__(self, phone_number: str, access_token: str):
        self.phone = phone_number
        self.token = access_token
        self.api_url = f"https://graph.facebook.com/v18.0/{phone_number}"

    def get_unread(self, filters: Optional[MessageFilter] = None) -> List[Message]:
        """WhatsApp doesn't support fetching message history"""
        raise NotImplementedError("WhatsApp doesn't support fetching message history")

    def get_recent(
        self,
        limit: int = 10,
        since: Optional[datetime] = None,
        filters: Optional[MessageFilter] = None,
    ) -> List[Message]:
        """WhatsApp doesn't support fetching message history"""
        raise NotImplementedError("WhatsApp doesn't support fetching message history")

    async def listen(
        self, filters: Optional[MessageFilter] = None, mark_read: bool = False
    ) -> AsyncIterator[Message]:
        """
        WhatsApp listening requires webhook setup.
        This would typically involve setting up a webhook endpoint
        and yielding messages as they're received via webhook.
        """
        raise NotImplementedError("WhatsApp listening requires webhook setup")

    def send(self, content: str, **kwargs) -> Message:
        """Send WhatsApp message"""
        to = kwargs.get("to")

        payload = {"messaging_product": "whatsapp", "to": to, "text": {"body": content}}

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        with httpx.Client() as client:
            response = client.post(
                f"{self.api_url}/messages", json=payload, headers=headers
            )
            result = response.json()

            message_id = result.get("messages", [{}])[0].get(
                "id", f"whatsapp-{datetime.now().isoformat()}"
            )

            return Message(
                id=message_id,
                platform_type="whatsapp",
                content=content,
                sender=self.phone,
                timestamp=datetime.now(timezone.utc),
                recipient=to,
                raw_data=result,
                platform_metadata={"sent": True, "messaging_product": "whatsapp"},
            )

    def reply(self, original_message: Message, content: str, **kwargs) -> Message:
        """Reply to a WhatsApp message"""

        # Extract sender from original message
        reply_to = original_message.sender
        if not reply_to:
            raise ValueError("Cannot determine sender from original message")

        # Optional: Quote the original message
        quote_original = kwargs.get("quote_original", False)
        reply_content = content

        if quote_original and original_message.content:
            # WhatsApp style quoting
            reply_content = f'"{original_message.content}"\n\n{content}'

        return self.send(content=reply_content, to=reply_to)
