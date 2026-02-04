# src/trivialmessage/gmail.py
# WIP - this is a work in progress module,
# needs more testing work before we rely on it in prod
import asyncio
import base64
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, AsyncIterator, Dict, List, Optional

import googleapiclient.discovery
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

from .common import Message, MessageFilter, MessagePlatform


class GmailPlatform(MessagePlatform):
    """Gmail implementation using Gmail API"""

    def __init__(
        self, credentials_path: Optional[str] = None, credentials: Optional[Any] = None
    ):
        """
        Initialize Gmail platform.

        Args:
            credentials_path: Path to credentials JSON file
            credentials: Pre-loaded credentials object
        """
        if credentials:
            self.creds = credentials
        elif credentials_path:
            self.creds = Credentials.from_authorized_user_file(credentials_path)
        else:
            raise ValueError("Must provide either credentials_path or credentials")

        # Refresh if needed
        if not self.creds.valid:
            if self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())

        self.service = googleapiclient.discovery.build(
            "gmail", "v1", credentials=self.creds
        )

    def _build_gmail_query(
        self, base_query: str, filters: Optional[MessageFilter]
    ) -> str:
        """Convert MessageFilter to Gmail search query"""
        query_parts = [base_query] if base_query else []

        if not filters:
            return " ".join(query_parts)

        if filters.sender:
            query_parts.append(f"from:{filters.sender}")
        if filters.recipient:
            query_parts.append(f"to:{filters.recipient}")
        if filters.subject_contains:
            query_parts.append(f'subject:"{filters.subject_contains}"')
        if filters.content_contains:
            query_parts.append(f'"{filters.content_contains}"')
        if filters.since:
            date_str = filters.since.strftime("%Y/%m/%d")
            query_parts.append(f"after:{date_str}")
        if filters.until:
            date_str = filters.until.strftime("%Y/%m/%d")
            query_parts.append(f"before:{date_str}")

        return " ".join(query_parts)

    def _convert_gmail_message(self, gmail_msg: Dict) -> Message:
        """Convert Gmail API message to Message object"""
        headers = {}
        payload = gmail_msg.get("payload", {})

        # Extract headers
        for header in payload.get("headers", []):
            headers[header["name"].lower()] = header["value"]

        # Extract body
        text_content = ""
        html_content = ""

        def extract_body(part):
            nonlocal text_content, html_content
            if "parts" in part:
                for subpart in part["parts"]:
                    extract_body(subpart)
            else:
                mime_type = part.get("mimeType", "")
                body_data = part.get("body", {}).get("data", "")

                if body_data:
                    try:
                        decoded = base64.urlsafe_b64decode(body_data).decode("utf-8")
                        if mime_type == "text/plain" and not text_content:
                            text_content = decoded
                        elif mime_type == "text/html" and not html_content:
                            html_content = decoded
                    except:
                        pass

        extract_body(payload)

        # Parse timestamp
        timestamp = datetime.now(timezone.utc)
        if headers.get("date"):
            try:
                # Parse email date format
                from email.utils import parsedate_to_datetime

                timestamp = parsedate_to_datetime(headers["date"])
            except:
                pass

        return Message(
            id=gmail_msg["id"],
            platform_type="gmail",
            content=text_content,
            sender=headers.get("from", ""),
            timestamp=timestamp,
            recipient=headers.get("to", ""),
            subject=headers.get("subject", ""),
            thread_id=gmail_msg.get("threadId"),
            in_reply_to=headers.get("in-reply-to"),
            html_content=html_content,
            raw_data=gmail_msg,
            platform_metadata={
                "label_ids": gmail_msg.get("labelIds", []),
                "message_id": headers.get("message-id", ""),
                "cc": headers.get("cc", ""),
                "bcc": headers.get("bcc", ""),
            },
        )

    def get_unread(self, filters: Optional[MessageFilter] = None) -> List[Message]:
        """Get unread messages synchronously"""
        query = self._build_gmail_query("is:unread", filters)

        results = self.service.users().messages().list(userId="me", q=query).execute()
        message_ids = [msg["id"] for msg in results.get("messages", [])]

        messages = []
        for msg_id in message_ids:
            msg = self.service.users().messages().get(userId="me", id=msg_id).execute()
            converted_msg = self._convert_gmail_message(msg)
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

        query = self._build_gmail_query("", merged_filters)

        results = (
            self.service.users()
            .messages()
            .list(userId="me", q=query, maxResults=limit)
            .execute()
        )

        message_ids = [msg["id"] for msg in results.get("messages", [])]

        messages = []
        for msg_id in message_ids:
            msg = self.service.users().messages().get(userId="me", id=msg_id).execute()
            converted_msg = self._convert_gmail_message(msg)
            if converted_msg.matches_filter(merged_filters):
                messages.append(converted_msg)

        return messages

    async def listen(
        self, filters: Optional[MessageFilter] = None, mark_read: bool = False
    ) -> AsyncIterator[Message]:
        """
        Gmail doesn't have real-time push without Pub/Sub setup.
        This implements polling-based listening.
        """
        last_history_id = None

        # Get initial history ID
        def get_history_id():
            profile = self.service.users().getProfile(userId="me").execute()
            return profile.get("historyId")

        last_history_id = await asyncio.to_thread(get_history_id)

        while True:
            try:

                def check_for_new():
                    current_profile = (
                        self.service.users().getProfile(userId="me").execute()
                    )
                    current_history_id = current_profile.get("historyId")

                    if last_history_id and current_history_id != last_history_id:
                        # Get history changes
                        history = (
                            self.service.users()
                            .history()
                            .list(userId="me", startHistoryId=last_history_id)
                            .execute()
                        )

                        new_messages = []
                        for record in history.get("history", []):
                            for msg_added in record.get("messagesAdded", []):
                                msg = msg_added.get("message", {})
                                # Only process if it's in INBOX (not sent, etc.)
                                if "INBOX" in msg.get("labelIds", []):
                                    full_msg = (
                                        self.service.users()
                                        .messages()
                                        .get(userId="me", id=msg["id"])
                                        .execute()
                                    )
                                    new_messages.append(
                                        self._convert_gmail_message(full_msg)
                                    )

                        return current_history_id, new_messages

                    return current_history_id, []

                history_id, new_messages = await asyncio.to_thread(check_for_new)
                last_history_id = history_id

                # Filter and yield messages
                for msg in new_messages:
                    if msg.matches_filter(filters):
                        if mark_read:
                            # Mark as read
                            await asyncio.to_thread(
                                lambda: self.service.users()
                                .messages()
                                .modify(
                                    userId="me",
                                    id=msg.id,
                                    body={"removeLabelIds": ["UNREAD"]},
                                )
                                .execute()
                            )
                        yield msg

                # Poll every 10 seconds
                await asyncio.sleep(10)

            except Exception as e:
                # Log error and continue
                print(f"Gmail listen error: {e}")
                await asyncio.sleep(30)

    def send(self, content: str, **kwargs) -> Message:
        """Send email message"""
        to = kwargs.get("to")
        subject = kwargs.get("subject", "")
        html = kwargs.get("html")
        cc = kwargs.get("cc")
        bcc = kwargs.get("bcc")

        if html:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(content, "plain"))
            msg.attach(MIMEText(html, "html"))
        else:
            msg = MIMEText(content)

        msg["Subject"] = subject
        msg["From"] = "me"  # Gmail API uses 'me' for authenticated user
        msg["To"] = to
        if cc:
            msg["Cc"] = cc
        if bcc:
            msg["Bcc"] = bcc

        raw_msg = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

        result = (
            self.service.users()
            .messages()
            .send(userId="me", body={"raw": raw_msg})
            .execute()
        )

        return Message(
            id=result.get("id"),
            platform_type="gmail",
            content=content,
            sender="me",  # Sent by authenticated user
            timestamp=datetime.now(timezone.utc),
            recipient=to,
            subject=subject,
            thread_id=result.get("threadId"),
            html_content=html,
            raw_data=result,
            platform_metadata={
                "cc": cc,
                "bcc": bcc,
            },
        )

    def reply(self, original_message: Message, content: str, **kwargs) -> Message:
        """Reply to a Gmail message with proper threading"""

        # Extract reply information
        reply_to = original_message.sender
        if not reply_to:
            raise ValueError("Cannot determine reply address from original message")

        # Handle subject
        original_subject = original_message.subject or ""
        if original_subject and not original_subject.lower().startswith("re:"):
            reply_subject = f"Re: {original_subject}"
        else:
            reply_subject = original_subject

        # Get thread ID for proper threading
        thread_id = original_message.thread_id

        # Optional quoting
        quote_original = kwargs.get("quote_original", False)
        reply_content = content

        if quote_original:
            original_text = original_message.content
            original_date = original_message.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            original_from = original_message.sender

            quoted_text = f"\n\nOn {original_date}, {original_from} wrote:\n"
            quoted_text += "\n".join(f"> {line}" for line in original_text.split("\n"))
            reply_content += quoted_text

        if kwargs.get("html"):
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(reply_content, "plain"))
            msg.attach(MIMEText(kwargs["html"], "html"))
        else:
            msg = MIMEText(reply_content)

        msg["Subject"] = reply_subject
        msg["From"] = "me"
        msg["To"] = reply_to

        # Set proper reply headers
        if original_message.in_reply_to:
            msg["In-Reply-To"] = original_message.in_reply_to
            msg["References"] = original_message.in_reply_to

        if kwargs.get("cc"):
            msg["Cc"] = kwargs["cc"]
        if kwargs.get("bcc"):
            msg["Bcc"] = kwargs["bcc"]

        raw_msg = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

        body = {"raw": raw_msg}
        if thread_id:
            body["threadId"] = thread_id

        result = self.service.users().messages().send(userId="me", body=body).execute()

        return Message(
            id=result.get("id"),
            platform_type="gmail",
            content=reply_content,
            sender="me",
            timestamp=datetime.now(timezone.utc),
            recipient=reply_to,
            subject=reply_subject,
            thread_id=result.get("threadId"),
            in_reply_to=original_message.in_reply_to,
            html_content=kwargs.get("html"),
            raw_data=result,
            platform_metadata={
                "cc": kwargs.get("cc"),
                "bcc": kwargs.get("bcc"),
                "is_reply": True,
                "original_message_id": original_message.id,
            },
        )
