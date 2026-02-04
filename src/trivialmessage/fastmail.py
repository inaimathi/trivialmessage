# src/trivialmessage/fastmail.py
import asyncio
from datetime import datetime, timezone
from typing import AsyncIterator, Dict, List, Optional

import httpx

from .common import Message, MessageFilter, MessagePlatform

JMAP_CORE = "urn:ietf:params:jmap:core"
JMAP_MAIL = "urn:ietf:params:jmap:mail"
JMAP_SUBMISSION = "urn:ietf:params:jmap:submission"

FASTMAIL_SESSION_URL = "https://api.fastmail.com/jmap/session"


class FastmailPlatform(MessagePlatform):
    """Fastmail implementation using the Fastmail JMAP API."""

    def __init__(self, api_token: str, account_id: str | None = None):
        """
        Initialize Fastmail platform with API token.

        Args:
            api_token: Fastmail API token with Mail + (for sending) Submission permissions
            account_id: Fastmail account ID (auto-detected if not provided)
        """
        self.api_token = api_token
        self.account_id = account_id

        # Filled from session:
        self.api_url: str | None = None
        self.upload_url: str | None = None
        self.download_url: str | None = None
        self.event_source_url: str | None = None
        self.session_state: str | None = None

        # Caches
        self._mailbox_role_cache: Dict[str, str] = {}
        self._identity_cache_by_email: Dict[str, str] = {}
        self._default_identity_id: str | None = None

        # Always load the JMAP session to discover apiUrl + primary accounts.
        self._load_session()

        # Ensure we have a mail account id.
        if not self.account_id:
            self.account_id = self._detect_mail_account_id()
        if not self.account_id:
            raise ValueError(
                "Could not determine Fastmail mail account id from session"
            )

    # -------------------------------------------------------------------------
    # Session / transport
    # -------------------------------------------------------------------------

    def _load_session(self) -> None:
        """Load Fastmail JMAP session, populate apiUrl and related endpoints."""
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(
                FASTMAIL_SESSION_URL,
                headers={"Authorization": f"Bearer {self.api_token}"},
            )

        if resp.status_code != 200:
            raise ValueError(
                f"Failed to authenticate with Fastmail API: "
                f"{resp.status_code} - {resp.text}"
            )

        session = resp.json()
        self.session_state = session.get("state")
        self.api_url = session.get("apiUrl")
        self.upload_url = session.get("uploadUrl")
        self.download_url = session.get("downloadUrl")
        self.event_source_url = session.get("eventSourceUrl")

        if not self.api_url:
            raise ValueError("Fastmail JMAP session did not include apiUrl")

        # If user supplied account_id, keep it; otherwise detect later from session.
        # (We still keep the session around via properties above.)
        self._session_json = session  # for debugging if needed

    def _detect_mail_account_id(self) -> str | None:
        """Return the primary mail account id from the loaded session."""
        session = getattr(self, "_session_json", {}) or {}
        primary = session.get("primaryAccounts", {}) or {}

        # Fastmail advertises the mail capability account id under this key.
        mail_acct = primary.get(JMAP_MAIL)
        if mail_acct:
            return mail_acct

        # Fallback: scan accounts
        accounts = session.get("accounts", {}) or {}
        for aid, info in accounts.items():
            caps = (info or {}).get("accountCapabilities", {}) or {}
            if JMAP_MAIL in caps:
                return aid
        return None

    def _make_jmap_request(
        self,
        method_calls: List[List],
        using: Optional[List[str]] = None,
    ) -> dict:
        """Make a synchronous JMAP request to Fastmail."""
        if not self.api_url:
            self._load_session()

        if using is None:
            using = [JMAP_CORE, JMAP_MAIL]

        payload = {"using": using, "methodCalls": method_calls}

        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                self.api_url,  # e.g. https://api.fastmail.com/jmap/api/
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )

        if resp.status_code != 200:
            raise OSError(
                f"Fastmail JMAP request failed: {resp.status_code} - {resp.text}"
            )
        return resp.json()

    async def _make_jmap_request_async(
        self,
        method_calls: List[List],
        using: Optional[List[str]] = None,
    ) -> dict:
        """Make an async JMAP request to Fastmail."""
        if not self.api_url:
            # session load is sync; do it in a thread to avoid blocking event loop
            await asyncio.to_thread(self._load_session)

        if using is None:
            using = [JMAP_CORE, JMAP_MAIL]

        payload = {"using": using, "methodCalls": method_calls}

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                self.api_url,
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )

        if resp.status_code != 200:
            raise OSError(
                f"Fastmail JMAP request failed: {resp.status_code} - {resp.text}"
            )
        return resp.json()

    # -------------------------------------------------------------------------
    # Filters / parsing
    # -------------------------------------------------------------------------

    def _build_email_filter(self, filters: Optional[MessageFilter]) -> dict:
        """Convert MessageFilter to JMAP Email/query filter."""
        cond: dict = {}
        if not filters:
            return cond

        if filters.sender:
            cond["from"] = filters.sender
        if filters.recipient:
            cond["to"] = filters.recipient
        if filters.subject_contains:
            cond["subject"] = filters.subject_contains
        if filters.content_contains:
            cond["text"] = filters.content_contains
        if filters.since:
            cond["after"] = filters.since.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        if filters.until:
            cond["before"] = filters.until.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

        return cond

    @staticmethod
    def _parse_received_at(v: str | None) -> datetime:
        if not v:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def _first_email(addr_list: object) -> str:
        if not isinstance(addr_list, list) or not addr_list:
            return ""
        first = addr_list[0] or {}
        if isinstance(first, dict):
            return first.get("email", "") or ""
        return ""

    @staticmethod
    def _extract_body_text(email_data: dict) -> tuple[str, str]:
        """
        Extract (text, html) content from JMAP Email object.

        When fetchTextBodyValues/fetchHTMLBodyValues are true, Email/get returns
        bodyValues keyed by partId, and textBody/htmlBody contain partIds.
        """
        body_values = email_data.get("bodyValues") or {}
        text_parts = email_data.get("textBody") or []
        html_parts = email_data.get("htmlBody") or []

        def part_value(part: dict) -> str:
            pid = (part or {}).get("partId")
            if not pid:
                return ""
            bv = body_values.get(pid) or {}
            return bv.get("value") or ""

        text = "\n".join([part_value(p) for p in text_parts if part_value(p)]).strip()
        html = "\n".join([part_value(p) for p in html_parts if part_value(p)]).strip()

        return text, html

    def _convert_fastmail_email(self, email_data: dict) -> Message:
        """Convert JMAP Email object to Message."""
        timestamp = self._parse_received_at(email_data.get("receivedAt"))

        text_content, html_content = self._extract_body_text(email_data)

        # fallback: preview if no bodies were fetched / present
        if not text_content:
            text_content = email_data.get("preview") or ""

        sender = self._first_email(email_data.get("from"))
        recipient = self._first_email(email_data.get("to"))

        subject = email_data.get("subject") or ""

        # Avoid duplicating HTML if it is identical to text.
        html_out = (
            html_content if html_content and html_content != text_content else None
        )

        return Message(
            id=email_data.get("id", ""),
            platform_type="fastmail",
            content=text_content,
            sender=sender,
            timestamp=timestamp,
            recipient=recipient,
            subject=subject,
            thread_id=email_data.get("threadId"),
            in_reply_to=email_data.get("inReplyTo"),
            html_content=html_out,
            raw_data=email_data,
            platform_metadata={
                "message_id": email_data.get("messageId"),
                "mailbox_ids": email_data.get("mailboxIds", {}),
                "keywords": email_data.get("keywords", {}),
                "size": email_data.get("size"),
                "preview": email_data.get("preview"),
            },
        )

    # -------------------------------------------------------------------------
    # Mailbox / identity helpers (for sending)
    # -------------------------------------------------------------------------

    def _mailbox_id_for_role(self, role: str, *, required: bool = True) -> str | None:
        """Return mailbox id for a role like 'drafts' or 'sent'."""
        if role in self._mailbox_role_cache:
            return self._mailbox_role_cache[role]

        call = [
            "Mailbox/query",
            {
                "accountId": self.account_id,
                "filter": {"role": role},
                "limit": 1,
            },
            f"mbq_{role}",
        ]

        res = self._make_jmap_request([call], using=[JMAP_CORE, JMAP_MAIL])
        mrs = res.get("methodResponses") or []
        if not mrs or mrs[0][0] != "Mailbox/query":
            if required:
                raise OSError(f"Mailbox/query failed for role={role!r}: {res}")
            return None

        ids = (mrs[0][1] or {}).get("ids") or []
        if not ids:
            if required:
                raise OSError(f"No mailbox found for role={role!r}")
            return None

        mid = ids[0]
        self._mailbox_role_cache[role] = mid
        return mid

    def _load_identities(self) -> None:
        """Fetch identities and populate cache."""
        call = ["Identity/get", {"accountId": self.account_id, "ids": None}, "id0"]
        res = self._make_jmap_request([call], using=[JMAP_CORE, JMAP_SUBMISSION])
        mrs = res.get("methodResponses") or []
        if not mrs or mrs[0][0] != "Identity/get":
            raise OSError(f"Identity/get failed: {res}")

        identities = (mrs[0][1] or {}).get("list") or []
        if not identities:
            raise OSError("Identity/get returned no identities")

        for ident in identities:
            email = (ident or {}).get("email") or ""
            iid = (ident or {}).get("id") or ""
            if email and iid:
                self._identity_cache_by_email[email.lower()] = iid

        # pick a default identity
        self._default_identity_id = (identities[0] or {}).get("id")

    def _identity_id(self, from_email: str | None) -> str:
        """Return identity id; if from_email provided, match it."""
        if not self._default_identity_id or not self._identity_cache_by_email:
            self._load_identities()

        if from_email:
            k = from_email.lower()
            iid = self._identity_cache_by_email.get(k)
            if not iid:
                raise OSError(f"No identity matches from_email={from_email!r}")
            return iid

        if not self._default_identity_id:
            raise OSError("No default identity available")
        return self._default_identity_id

    # -------------------------------------------------------------------------
    # Fetch
    # -------------------------------------------------------------------------

    def _fetch_emails(
        self, email_filter: dict | None = None, limit: int = 50
    ) -> List[Message]:
        """Fetch emails using JMAP Email/query + Email/get."""
        query_call = [
            "Email/query",
            {
                "accountId": self.account_id,
                "filter": email_filter or {},
                "sort": [{"property": "receivedAt", "isAscending": False}],
                "limit": limit,
            },
            "q0",
        ]

        qres = self._make_jmap_request([query_call], using=[JMAP_CORE, JMAP_MAIL])
        mrs = qres.get("methodResponses") or []
        if not mrs or mrs[0][0] != "Email/query":
            return []

        email_ids = (mrs[0][1] or {}).get("ids") or []
        if not email_ids:
            return []

        get_call = [
            "Email/get",
            {
                "accountId": self.account_id,
                "ids": email_ids,
                "properties": [
                    "id",
                    "messageId",
                    "threadId",
                    "subject",
                    "from",
                    "to",
                    "cc",
                    "bcc",
                    "receivedAt",
                    "keywords",
                    "mailboxIds",
                    "size",
                    "preview",
                    "inReplyTo",
                    "textBody",
                    "htmlBody",
                    "bodyValues",
                ],
                # Pull bodyValues.value for text/html bodies
                "fetchTextBodyValues": True,
                "fetchHTMLBodyValues": True,
                # Keep body part entries small but include what we need
                "bodyProperties": ["partId", "type", "charset"],
            },
            "g0",
        ]

        gres = self._make_jmap_request([get_call], using=[JMAP_CORE, JMAP_MAIL])
        mrs = gres.get("methodResponses") or []
        if not mrs or mrs[0][0] != "Email/get":
            return []

        emails = (mrs[0][1] or {}).get("list") or []
        out: List[Message] = []
        for email_data in emails:
            try:
                out.append(self._convert_fastmail_email(email_data))
            except Exception as e:
                # keep going
                print(f"Error converting email {email_data.get('id', 'unknown')}: {e}")
        return out

    def get_unread(self, filters: Optional[MessageFilter] = None) -> List[Message]:
        """Get unread emails."""
        cond = self._build_email_filter(filters)
        cond["hasKeyword"] = "$seen"
        email_filter = {"operator": "NOT", "conditions": [cond]}

        messages = self._fetch_emails(email_filter)
        return [m for m in messages if m.matches_filter(filters)]

    def get_recent(
        self,
        limit: int = 10,
        since: Optional[datetime] = None,
        filters: Optional[MessageFilter] = None,
    ) -> List[Message]:
        """Get recent emails."""
        merged = filters or MessageFilter()
        if since:
            merged.since = since

        email_filter = self._build_email_filter(merged)
        messages = self._fetch_emails(email_filter, limit)
        return [m for m in messages if m.matches_filter(merged)]

    # -------------------------------------------------------------------------
    # Listen (polling)
    # -------------------------------------------------------------------------

    async def listen(
        self, filters: Optional[MessageFilter] = None, mark_read: bool = False
    ) -> AsyncIterator[Message]:
        """
        Listen for new emails using polling.

        For production, consider Fastmail's EventSource API (eventSourceUrl in session)
        for push notifications and faster resync.
        """
        last_check = datetime.now(timezone.utc)

        while True:
            try:
                current_time = datetime.now(timezone.utc)

                merged = filters or MessageFilter()
                merged.since = last_check
                email_filter = self._build_email_filter(merged)

                query_call = [
                    "Email/query",
                    {
                        "accountId": self.account_id,
                        "filter": email_filter,
                        "sort": [{"property": "receivedAt", "isAscending": False}],
                        "limit": 50,
                    },
                    "q0",
                ]

                qres = await self._make_jmap_request_async(
                    [query_call], using=[JMAP_CORE, JMAP_MAIL]
                )
                mrs = qres.get("methodResponses") or []
                if not mrs or mrs[0][0] != "Email/query":
                    last_check = current_time
                    await asyncio.sleep(30)
                    continue

                email_ids = (mrs[0][1] or {}).get("ids") or []
                if not email_ids:
                    last_check = current_time
                    await asyncio.sleep(30)
                    continue

                get_call = [
                    "Email/get",
                    {
                        "accountId": self.account_id,
                        "ids": email_ids,
                        "properties": [
                            "id",
                            "messageId",
                            "threadId",
                            "subject",
                            "from",
                            "to",
                            "receivedAt",
                            "keywords",
                            "mailboxIds",
                            "preview",
                            "inReplyTo",
                            "textBody",
                            "htmlBody",
                            "bodyValues",
                        ],
                        "fetchTextBodyValues": True,
                        "fetchHTMLBodyValues": True,
                        "bodyProperties": ["partId", "type", "charset"],
                    },
                    "g0",
                ]

                gres = await self._make_jmap_request_async(
                    [get_call], using=[JMAP_CORE, JMAP_MAIL]
                )
                mrs = gres.get("methodResponses") or []
                if not mrs or mrs[0][0] != "Email/get":
                    last_check = current_time
                    await asyncio.sleep(30)
                    continue

                emails = (mrs[0][1] or {}).get("list") or []
                for email_data in emails:
                    try:
                        msg = self._convert_fastmail_email(email_data)
                        if msg.matches_filter(filters):
                            if mark_read and msg.id:
                                await self._mark_as_read(msg.id)
                            yield msg
                    except Exception as e:
                        print(f"Error processing email: {e}")

                last_check = current_time
                await asyncio.sleep(30)

            except Exception as e:
                print(f"Fastmail listen error: {e}")
                await asyncio.sleep(60)

    async def _mark_as_read(self, email_id: str) -> None:
        """Mark an email as read by adding the $seen keyword."""
        try:
            set_call = [
                "Email/set",
                {
                    "accountId": self.account_id,
                    "update": {email_id: {"keywords/$seen": True}},
                },
                "s0",
            ]
            await self._make_jmap_request_async(
                [set_call], using=[JMAP_CORE, JMAP_MAIL]
            )
        except Exception as e:
            print(f"Failed to mark email as read: {e}")

    # -------------------------------------------------------------------------
    # Send / Reply
    # -------------------------------------------------------------------------

    def send(self, content: str, **kwargs) -> Message:
        """Send email via Fastmail JMAP (Email/set draft + EmailSubmission/set)."""
        to = kwargs.get("to")
        if not to:
            raise ValueError("'to' recipient is required")

        subject = kwargs.get("subject", "") or ""
        html = kwargs.get("html")
        cc = kwargs.get("cc")
        bcc = kwargs.get("bcc")
        from_email = kwargs.get("from_email")

        drafts_mailbox_id = self._mailbox_id_for_role("drafts", required=True)
        sent_mailbox_id = self._mailbox_id_for_role("sent", required=False)
        identity_id = self._identity_id(from_email)

        # Build Email object using bodyValues (JMAP-compatible).
        email_obj: dict = {
            "to": [{"email": to}],
            "subject": subject,
            "mailboxIds": {drafts_mailbox_id: True},
            "keywords": {"$draft": True},
            "textBody": [{"partId": "t1", "type": "text/plain"}],
            "bodyValues": {"t1": {"charset": "utf-8", "value": content}},
        }

        if from_email:
            email_obj["from"] = [{"email": from_email}]
        if cc:
            email_obj["cc"] = [{"email": cc}]
        if bcc:
            email_obj["bcc"] = [{"email": bcc}]

        if html:
            email_obj["htmlBody"] = [{"partId": "h1", "type": "text/html"}]
            email_obj["bodyValues"]["h1"] = {"charset": "utf-8", "value": html}

        # Two method calls in ONE request, using backreferences.
        email_set_call = [
            "Email/set",
            {"accountId": self.account_id, "create": {"draft": email_obj}},
            "0",
        ]

        submission_args: dict = {
            "accountId": self.account_id,
            "create": {
                "sendIt": {
                    # Reference the created Email id from Email/set create id "draft"
                    "emailId": "#draft",
                    "identityId": identity_id,
                }
            },
        }

        if sent_mailbox_id:
            # Prefer moving draft -> sent and removing $draft.
            # onSuccessUpdateEmail expects a map keyed by submission creation id (#sendIt)
            # to a patch object applied to the Email referenced by that submission.
            submission_args["onSuccessUpdateEmail"] = {
                "#sendIt": {
                    f"mailboxIds/{drafts_mailbox_id}": None,
                    f"mailboxIds/{sent_mailbox_id}": True,
                    "keywords/$draft": None,
                }
            }
        else:
            # Fallback: just delete the draft after send succeeds.
            submission_args["onSuccessDestroyEmail"] = ["#draft"]

        submission_call = ["EmailSubmission/set", submission_args, "1"]

        res = self._make_jmap_request(
            [email_set_call, submission_call],
            using=[JMAP_CORE, JMAP_MAIL, JMAP_SUBMISSION],
        )

        mrs = res.get("methodResponses") or []
        if not mrs or mrs[0][0] != "Email/set":
            raise OSError(f"Email creation failed: {res}")

        created = (mrs[0][1] or {}).get("created") or {}
        not_created = (mrs[0][1] or {}).get("notCreated") or {}
        if not_created:
            raise OSError(f"Email creation failed: {list(not_created.values())[0]}")
        if "draft" not in created or "id" not in (created.get("draft") or {}):
            raise OSError(f"Email creation failed: {created}")

        draft_id = created["draft"]["id"]

        # Check submission response for errors (optional but helps debugging)
        if len(mrs) > 1 and mrs[1][0] == "EmailSubmission/set":
            not_sub_created = (mrs[1][1] or {}).get("notCreated") or {}
            if not_sub_created:
                raise OSError(
                    f"Email submission failed: {list(not_sub_created.values())[0]}"
                )

        return Message(
            id=draft_id,
            platform_type="fastmail",
            content=content,
            sender=from_email or "me",
            timestamp=datetime.now(timezone.utc),
            recipient=to,
            subject=subject,
            html_content=html,
            raw_data=res,
            platform_metadata={"cc": cc, "bcc": bcc, "sent": True},
        )

    async def send_async(self, content: str, **kwargs) -> Message:
        """
        Async version of send().
        This avoids blocking the event loop (useful when replying inside listen()).
        """
        to = kwargs.get("to")
        if not to:
            raise ValueError("'to' recipient is required")

        subject = kwargs.get("subject", "") or ""
        html = kwargs.get("html")
        cc = kwargs.get("cc")
        bcc = kwargs.get("bcc")
        from_email = kwargs.get("from_email")

        # mailbox/identity helpers are sync; do them in threads if needed
        drafts_mailbox_id = await asyncio.to_thread(
            self._mailbox_id_for_role, "drafts", True
        )
        sent_mailbox_id = await asyncio.to_thread(
            self._mailbox_id_for_role, "sent", False
        )
        identity_id = await asyncio.to_thread(self._identity_id, from_email)

        email_obj: dict = {
            "to": [{"email": to}],
            "subject": subject,
            "mailboxIds": {drafts_mailbox_id: True},
            "keywords": {"$draft": True},
            "textBody": [{"partId": "t1", "type": "text/plain"}],
            "bodyValues": {"t1": {"charset": "utf-8", "value": content}},
        }

        if from_email:
            email_obj["from"] = [{"email": from_email}]
        if cc:
            email_obj["cc"] = [{"email": cc}]
        if bcc:
            email_obj["bcc"] = [{"email": bcc}]

        if html:
            email_obj["htmlBody"] = [{"partId": "h1", "type": "text/html"}]
            email_obj["bodyValues"]["h1"] = {"charset": "utf-8", "value": html}

        email_set_call = [
            "Email/set",
            {"accountId": self.account_id, "create": {"draft": email_obj}},
            "0",
        ]

        submission_args: dict = {
            "accountId": self.account_id,
            "create": {"sendIt": {"emailId": "#draft", "identityId": identity_id}},
        }

        if sent_mailbox_id:
            submission_args["onSuccessUpdateEmail"] = {
                "#sendIt": {
                    f"mailboxIds/{drafts_mailbox_id}": None,
                    f"mailboxIds/{sent_mailbox_id}": True,
                    "keywords/$draft": None,
                }
            }
        else:
            submission_args["onSuccessDestroyEmail"] = ["#draft"]

        submission_call = ["EmailSubmission/set", submission_args, "1"]

        res = await self._make_jmap_request_async(
            [email_set_call, submission_call],
            using=[JMAP_CORE, JMAP_MAIL, JMAP_SUBMISSION],
        )

        mrs = res.get("methodResponses") or []
        if not mrs or mrs[0][0] != "Email/set":
            raise OSError(f"Email creation failed: {res}")

        created = (mrs[0][1] or {}).get("created") or {}
        not_created = (mrs[0][1] or {}).get("notCreated") or {}
        if not_created:
            raise OSError(f"Email creation failed: {list(not_created.values())[0]}")
        if "draft" not in created or "id" not in (created.get("draft") or {}):
            raise OSError(f"Email creation failed: {created}")

        draft_id = created["draft"]["id"]

        if len(mrs) > 1 and mrs[1][0] == "EmailSubmission/set":
            not_sub_created = (mrs[1][1] or {}).get("notCreated") or {}
            if not_sub_created:
                raise OSError(
                    f"Email submission failed: {list(not_sub_created.values())[0]}"
                )

        return Message(
            id=draft_id,
            platform_type="fastmail",
            content=content,
            sender=from_email or "me",
            timestamp=datetime.now(timezone.utc),
            recipient=to,
            subject=subject,
            html_content=html,
            raw_data=res,
            platform_metadata={"cc": cc, "bcc": bcc, "sent": True},
        )

    def reply(self, original_message: Message, content: str, **kwargs) -> Message:
        """Reply to an email (sync)."""
        reply_to = original_message.sender
        if not reply_to:
            raise ValueError("Cannot determine reply address from original message")

        original_subject = original_message.subject or ""
        if original_subject and not original_subject.lower().startswith("re:"):
            reply_subject = f"Re: {original_subject}"
        else:
            reply_subject = original_subject

        quote_original = kwargs.get("quote_original", False)
        reply_content = content

        if quote_original:
            original_text = original_message.content or ""
            original_date = original_message.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            original_from = original_message.sender or ""

            quoted_text = f"\n\nOn {original_date}, {original_from} wrote:\n"
            quoted_text += "\n".join(f"> {line}" for line in original_text.split("\n"))
            reply_content += quoted_text

        return self.send(
            content=reply_content,
            to=reply_to,
            subject=reply_subject,
            html=kwargs.get("html"),
            cc=kwargs.get("cc"),
            bcc=kwargs.get("bcc"),
            from_email=kwargs.get("from_email"),
        )

    async def reply_async(
        self, original_message: Message, content: str, **kwargs
    ) -> Message:
        """Reply to an email (async)."""
        reply_to = original_message.sender
        if not reply_to:
            raise ValueError("Cannot determine reply address from original message")

        original_subject = original_message.subject or ""
        if original_subject and not original_subject.lower().startswith("re:"):
            reply_subject = f"Re: {original_subject}"
        else:
            reply_subject = original_subject

        quote_original = kwargs.get("quote_original", False)
        reply_content = content

        if quote_original:
            original_text = original_message.content or ""
            original_date = original_message.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            original_from = original_message.sender or ""

            quoted_text = f"\n\nOn {original_date}, {original_from} wrote:\n"
            quoted_text += "\n".join(f"> {line}" for line in original_text.split("\n"))
            reply_content += quoted_text

        return await self.send_async(
            content=reply_content,
            to=reply_to,
            subject=reply_subject,
            html=kwargs.get("html"),
            cc=kwargs.get("cc"),
            bcc=kwargs.get("bcc"),
            from_email=kwargs.get("from_email"),
        )
