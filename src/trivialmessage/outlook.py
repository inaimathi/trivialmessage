# src/trivialmessage/outlook.py
# WIP - this is a work in progress module,
# needs more testing work before we rely on it in prod
import asyncio
from datetime import datetime, timezone
from typing import AsyncIterator, Dict, List, Optional

import httpx
import msal

from .common import Message, MessageFilter, MessagePlatform


class OutlookPlatform(MessagePlatform):
    """Outlook implementation using Microsoft Graph API"""

    def __init__(
        self, client_id: str, client_secret: str, tenant_id: str, user_id: str = "me"
    ):
        """
        Initialize Outlook platform with app credentials.

        For production, you'd want to handle user authentication properly.
        """
        self.client_id = client_id
        self.user_id = user_id

        # Create MSAL app
        self.app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )

        self.token = self._get_access_token()

    def _get_access_token(self) -> str:
        """Get access token using client credentials flow"""
        result = self.app.acquire_token_silent(
            scopes=["https://graph.microsoft.com/.default"], account=None
        )

        if not result:
            result = self.app.acquire_token_for_client(
                scopes=["https://graph.microsoft.com/.default"]
            )

        if "access_token" not in result:
            raise Exception(f"Could not obtain access token: {result}")

        return result["access_token"]

    def _build_graph_filter(self, filters: Optional[MessageFilter]) -> str:
        """Convert MessageFilter to Graph API $filter parameter"""
        filter_parts = []

        if not filters:
            return ""

        if filters.sender:
            filter_parts.append(f"from/emailAddress/address eq '{filters.sender}'")
        if filters.subject_contains:
            filter_parts.append(f"contains(subject, '{filters.subject_contains}')")
        if filters.since:
            iso_date = filters.since.isoformat()
            filter_parts.append(f"receivedDateTime ge {iso_date}")
        if filters.until:
            iso_date = filters.until.isoformat()
            filter_parts.append(f"receivedDateTime le {iso_date}")

        return " and ".join(filter_parts)

    def _convert_graph_message(self, graph_msg: Dict) -> Message:
        """Convert Graph API message to Message object"""

        # Parse timestamp
        timestamp = datetime.now(timezone.utc)
        if graph_msg.get("receivedDateTime"):
            try:
                timestamp = datetime.fromisoformat(
                    graph_msg["receivedDateTime"].replace("Z", "+00:00")
                )
            except:
                pass

        # Extract content based on content type
        body = graph_msg.get("body", {})
        content_type = body.get("contentType", "text")
        content = body.get("content", "")

        text_content = content if content_type == "text" else ""
        html_content = content if content_type == "html" else ""

        return Message(
            id=graph_msg.get("id"),
            platform_type="outlook",
            content=text_content or html_content,  # Use HTML as fallback if no text
            sender=graph_msg.get("from", {}).get("emailAddress", {}).get("address", ""),
            timestamp=timestamp,
            recipient=", ".join(
                [
                    addr.get("emailAddress", {}).get("address", "")
                    for addr in graph_msg.get("toRecipients", [])
                ]
            ),
            subject=graph_msg.get("subject", ""),
            conversation_id=graph_msg.get("conversationId"),
            in_reply_to=graph_msg.get("internetMessageId"),
            html_content=html_content if html_content != text_content else None,
            raw_data=graph_msg,
            platform_metadata={
                "cc": ", ".join(
                    [
                        addr.get("emailAddress", {}).get("address", "")
                        for addr in graph_msg.get("ccRecipients", [])
                    ]
                ),
                "bcc": ", ".join(
                    [
                        addr.get("emailAddress", {}).get("address", "")
                        for addr in graph_msg.get("bccRecipients", [])
                    ]
                ),
                "is_read": graph_msg.get("isRead", False),
                "importance": graph_msg.get("importance", "normal"),
                "internet_message_id": graph_msg.get("internetMessageId", ""),
            },
        )

    async def _make_graph_request(
        self, url: str, method: str = "GET", data: Dict = None
    ) -> Dict:
        """Make authenticated request to Graph API"""
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient() as client:
            if method == "GET":
                response = await client.get(url, headers=headers)
                return response.json()
            elif method == "POST":
                response = await client.post(url, headers=headers, json=data)
                return response.json()
            elif method == "PATCH":
                response = await client.patch(url, headers=headers, json=data)
                return response.json()

    def _make_graph_request_sync(
        self, url: str, method: str = "GET", data: Dict = None
    ) -> Dict:
        """Make authenticated request to Graph API synchronously"""
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        with httpx.Client() as client:
            if method == "GET":
                response = client.get(url, headers=headers)
                return response.json()
            elif method == "POST":
                response = client.post(url, headers=headers, json=data)
                return response.json()
            elif method == "PATCH":
                response = client.patch(url, headers=headers, json=data)
                return response.json()

    def get_unread(self, filters: Optional[MessageFilter] = None) -> List[Message]:
        """Get unread messages synchronously"""
        base_filter = "isRead eq false"
        additional_filter = self._build_graph_filter(filters)

        full_filter = base_filter
        if additional_filter:
            full_filter += f" and {additional_filter}"

        url = f"https://graph.microsoft.com/v1.0/users/{self.user_id}/messages"
        if full_filter:
            url += f"?$filter={full_filter}"

        result = self._make_graph_request_sync(url)

        messages = []
        for msg in result.get("value", []):
            converted_msg = self._convert_graph_message(msg)
            if converted_msg.matches_filter(filters):
                messages.append(converted_msg)

        return messages

    def get_recent(
        self,
        limit: int = 10,
        since: Optional[datetime] = None,
        filters: Optional[MessageFilter] = None,
    ) -> List[Message]:
        """Get recent messages synchronously"""
        # Merge since parameter with filters
        merged_filters = filters or MessageFilter()
        if since:
            merged_filters.since = since

        additional_filter = self._build_graph_filter(merged_filters)

        url = f"https://graph.microsoft.com/v1.0/users/{self.user_id}/messages?$top={limit}&$orderby=receivedDateTime desc"
        if additional_filter:
            url += f"&$filter={additional_filter}"

        result = self._make_graph_request_sync(url)

        messages = []
        for msg in result.get("value", []):
            converted_msg = self._convert_graph_message(msg)
            if converted_msg.matches_filter(merged_filters):
                messages.append(converted_msg)

        return messages

    async def listen(
        self, filters: Optional[MessageFilter] = None, mark_read: bool = False
    ) -> AsyncIterator[Message]:
        """
        Polling-based listening for Outlook.
        For production, you'd want to set up webhook subscriptions.
        """
        last_check = datetime.now(timezone.utc)

        while True:
            try:
                current_time = datetime.now(timezone.utc)

                # Get messages since last check
                merged_filters = filters or MessageFilter()
                merged_filters.since = last_check

                new_messages = self.get_recent(limit=100, filters=merged_filters)

                for msg in new_messages:
                    if mark_read and not msg.platform_metadata.get("is_read", True):
                        # Mark as read
                        await self._make_graph_request(
                            f"https://graph.microsoft.com/v1.0/users/{self.user_id}/messages/{msg.id}",
                            method="PATCH",
                            data={"isRead": True},
                        )
                    yield msg

                last_check = current_time
                await asyncio.sleep(30)  # Poll every 30 seconds

            except Exception as e:
                print(f"Outlook listen error: {e}")
                await asyncio.sleep(60)

    def send(self, content: str, **kwargs) -> Message:
        """Send email message"""
        to = kwargs.get("to")
        subject = kwargs.get("subject", "")
        html = kwargs.get("html")
        cc = kwargs.get("cc")
        bcc = kwargs.get("bcc")

        message = {
            "subject": subject,
            "body": {
                "contentType": "html" if html else "text",
                "content": html if html else content,
            },
            "toRecipients": [{"emailAddress": {"address": to}}] if to else [],
        }

        if cc:
            message["ccRecipients"] = [{"emailAddress": {"address": cc}}]
        if bcc:
            message["bccRecipients"] = [{"emailAddress": {"address": bcc}}]

        url = f"https://graph.microsoft.com/v1.0/users/{self.user_id}/sendMail"
        data = {"message": message}

        result = self._make_graph_request_sync(url, method="POST", data=data)

        return Message(
            id=f"sent-{datetime.now().isoformat()}",  # Graph API doesn't return message ID for sent emails
            platform_type="outlook",
            content=content,
            sender=self.user_id,
            timestamp=datetime.now(timezone.utc),
            recipient=to,
            subject=subject,
            html_content=html,
            raw_data=result,
            platform_metadata={"cc": cc, "bcc": bcc, "sent": True},
        )

    def reply(self, original_message: Message, content: str, **kwargs) -> Message:
        """Reply to an Outlook message using Graph API reply endpoint"""

        message_id = original_message.id
        if not message_id:
            raise ValueError("Cannot determine message ID from original message")

        # Optional quoting
        quote_original = kwargs.get("quote_original", False)
        reply_content = content

        if quote_original:
            original_text = original_message.content
            original_date = original_message.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            original_from = original_message.sender

            quoted_text = f"\n\n-----Original Message-----\nFrom: {original_from}\nSent: {original_date}\n\n{original_text}"
            reply_content += quoted_text

        # Use Graph API's reply endpoint which handles threading automatically
        reply_data = {
            "message": {
                "body": {
                    "contentType": "html" if kwargs.get("html") else "text",
                    "content": (
                        kwargs.get("html", reply_content)
                        if kwargs.get("html")
                        else reply_content
                    ),
                }
            }
        }

        # Add additional recipients if specified
        if kwargs.get("cc"):
            reply_data["message"]["ccRecipients"] = [
                {"emailAddress": {"address": kwargs["cc"]}}
            ]

        url = f"https://graph.microsoft.com/v1.0/users/{self.user_id}/messages/{message_id}/reply"
        result = self._make_graph_request_sync(url, method="POST", data=reply_data)

        return Message(
            id=f"reply-{datetime.now().isoformat()}",  # Graph API doesn't return message ID for replies
            platform_type="outlook",
            content=reply_content,
            sender=self.user_id,
            timestamp=datetime.now(timezone.utc),
            recipient=original_message.sender,
            subject=(
                f"Re: {original_message.subject}" if original_message.subject else "Re:"
            ),
            thread_id=original_message.conversation_id,
            in_reply_to=original_message.in_reply_to,
            html_content=kwargs.get("html"),
            raw_data=result,
            platform_metadata={
                "cc": kwargs.get("cc"),
                "is_reply": True,
                "original_message_id": original_message.id,
                "sent": True,
            },
        )
