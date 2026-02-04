# src/trivialmessage/smtp.py
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import AsyncIterator, List, Optional, Sequence

from .common import Message, MessageFilter, MessagePlatform


def _split_addrs(v: object) -> List[str]:
    """
    Accept:
      - "a@b.com, c@d.com"
      - ["a@b.com", "c@d.com"]
    Return list of non-empty, stripped addresses.
    """
    if not v:
        return []
    if isinstance(v, (list, tuple, set)):
        out = []
        for x in v:
            s = str(x or "").strip()
            if s:
                out.append(s)
        return out
    # string-ish
    s = str(v).strip()
    if not s:
        return []
    return [a.strip() for a in s.split(",") if a.strip()]


class SMTPPlatform(MessagePlatform):
    """Generic SMTP implementation for sending emails through any SMTP server."""

    def __init__(
        self,
        smtp_server: str,
        smtp_port: int = 587,
        username: str | None = None,
        password: str | None = None,
        from_email: str | None = None,
        use_tls: bool = True,
        use_ssl: bool = False,
    ):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email or username
        self.use_tls = use_tls
        self.use_ssl = use_ssl

        if not self.from_email:
            raise ValueError("Must provide either from_email or username")

    def _create_smtp_connection(self) -> smtplib.SMTP:
        """Create and configure SMTP connection."""
        if self.use_ssl:
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
        else:
            smtp = smtplib.SMTP(self.smtp_server, self.smtp_port)

        # Best practice: EHLO before STARTTLS, and again after.
        try:
            smtp.ehlo()
        except Exception:
            pass

        if self.use_tls and not self.use_ssl:
            smtp.starttls()
            try:
                smtp.ehlo()
            except Exception:
                pass

        if self.username and self.password:
            smtp.login(self.username, self.password)

        return smtp

    def get_unread(self, filters: Optional[MessageFilter] = None) -> List[Message]:
        raise NotImplementedError(
            "SMTP is send-only. Use IMAP/POP3 platforms for receiving messages."
        )

    def get_recent(
        self,
        limit: int = 10,
        since: Optional[datetime] = None,
        filters: Optional[MessageFilter] = None,
    ) -> List[Message]:
        raise NotImplementedError(
            "SMTP is send-only. Use IMAP/POP3 platforms for receiving messages."
        )

    async def listen(
        self, filters: Optional[MessageFilter] = None, mark_read: bool = False
    ) -> AsyncIterator[Message]:
        raise NotImplementedError(
            "SMTP is send-only. Use IMAP/POP3 platforms for listening to messages."
        )
        if False:
            yield  # pragma: no cover

    def send(self, content: str, **kwargs) -> Message:
        """Send email via SMTP."""
        to_addrs = _split_addrs(kwargs.get("to"))
        if not to_addrs:
            raise ValueError("'to' recipient is required")

        subject = str(kwargs.get("subject", "") or "")
        html = kwargs.get("html")
        cc_addrs = _split_addrs(kwargs.get("cc"))
        bcc_addrs = _split_addrs(kwargs.get("bcc"))
        from_email = str(kwargs.get("from_email", self.from_email) or self.from_email)

        # Build message
        if html:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(content, "plain"))
            msg.attach(MIMEText(str(html), "html"))
        else:
            msg = MIMEText(content)

        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = ", ".join(to_addrs)
        if cc_addrs:
            msg["Cc"] = ", ".join(cc_addrs)
        # NOTE: We intentionally do not add a "Bcc" header; recipients are handled via to_addrs.

        recipients: List[str] = []
        recipients.extend(to_addrs)
        recipients.extend(cc_addrs)
        recipients.extend(bcc_addrs)

        with self._create_smtp_connection() as smtp:
            smtp.send_message(msg, from_addr=from_email, to_addrs=recipients)

        return Message(
            id=f"smtp-{datetime.now(timezone.utc).isoformat()}",
            platform_type="smtp",
            content=content,
            sender=from_email,
            timestamp=datetime.now(timezone.utc),
            recipient=", ".join(to_addrs),
            subject=subject,
            html_content=str(html) if html else None,
            raw_data={
                "server": self.smtp_server,
                "port": self.smtp_port,
                "use_tls": self.use_tls,
                "use_ssl": self.use_ssl,
            },
            platform_metadata={
                "cc": ", ".join(cc_addrs) if cc_addrs else None,
                "bcc": ", ".join(bcc_addrs) if bcc_addrs else None,
                "sent": True,
                "smtp_server": self.smtp_server,
            },
        )

    def reply(self, original_message: Message, content: str, **kwargs) -> Message:
        """Reply to a message via SMTP."""
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
            original_date = original_message.timestamp.astimezone(
                timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S %Z")
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
