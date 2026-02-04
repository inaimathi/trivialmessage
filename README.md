# TrivialMessage

A small, composable library that normalizes “messages” from different platforms (email today; others later) behind a single interface.

The goal is to make it easy to:

- fetch unread messages (polling),
- listen for new messages (async generators),
- send/reply/forward when supported,
- apply consistent filtering (sender/recipient/subject/time windows),
- keep datetimes normalized to UTC.

> Note: Several platforms (Gmail/Outlook/Slack/WhatsApp) are intentionally **WIP** and may be stubbed or absent.

---

## Installation

Base install (interfaces + core models/utilities):

```bash
pip install trivialmessage
````

Email support (Fastmail + IMAP/SMTP helpers):

```bash
pip install "trivialmessage[email]"
```

If you keep Protonmail Bridge support in this library (optional):

```bash
pip install "trivialmessage[protonmail]"
```

---

## Concepts

### Message

All platforms yield a `Message` object (or a dict with the same shape, depending on your integration layer). The message is intended to be JSON-friendly and stable across sources.

Typical fields:

* `message_id` (stable external id if available)
* `from`, `to`, `cc`, `bcc`
* `subject`
* `text`, `html`
* `date` (send-time, if known) **normalized to UTC**
* `internaldate` (receive-time, if known) **normalized to UTC**
* `raw_headers` (dict of headers when available)
* platform-specific metadata (e.g. `uid` for IMAP-like sources)

### Filters

Platforms accept a `MessageFilter` (or a list of them) to limit what you fetch/listen to.

Common filter fields:

* sender/recipient matching should be **case-insensitive** (addresses are normalized)
* datetime comparisons should be against **UTC-aware** datetimes

Example filter patterns you’ll commonly want:

* “from is in allowlist”
* “to contains support@…”
* “subject contains keyword”
* “received since <time>”
* “only unread”

---

## Platform API

All platforms implement the same general interface (some methods may raise `NotImplementedError` / `PlatformNotSupported` if the platform can’t do that operation).

### Core methods

* `get_unread(filters=...) -> list[Message]`
  Fetch unread messages (polling style).

* `listen(filters=..., **opts) -> AsyncIterator[Message]`
  Yield messages as they arrive. Must not block other platforms if you compose multiple listeners.

* `send(to, subject, text=None, html=None, cc=None, bcc=None, **opts) -> Message`
  Send a new outbound message.

* `reply(message, text=None, html=None, **opts) -> Message`
  Reply to an existing inbound message.

* `forward(message, to, text=None, html=None, **opts) -> Message`
  Forward an existing message to a new recipient.

### Capability notes

Not every platform can both send and receive.

* Some platforms are **receive-only** (e.g., IMAP if you only configure IMAP and no SMTP).
* Some platforms are **send-only** (e.g., SMTP-only configuration).
* If a method is unsupported, it should fail fast with a clear exception.

---

## Platforms

### Fastmail

Fastmail is treated as a first-class platform (HTTP API).

#### Credentials

You’ll need an API token from Fastmail.

High-level steps:

1. Log in to Fastmail.
2. Create an API token in Fastmail settings (app/password/token section).
3. Provide it to the platform via env var or explicit constructor argument.

Common env var:

* `FASTMAIL_API_TOKEN` (your token)

#### Usage

```python
import asyncio

from trivialmessage.platform.fastmail import FastmailPlatform
from trivialmessage.types import MessageFilter  # name may vary in your codebase

fm = FastmailPlatform.from_env()

# Poll unread
msgs = fm.get_unread(filters=[
    MessageFilter(from_email="alerts@example.com"),
])

# Listen for new mail
async def main():
    async for msg in fm.listen(filters=[MessageFilter(any_recipient="me@mydomain.com")]):
        print(msg.subject)

asyncio.run(main())
```

#### Platform-specific concerns

* Fastmail provides stable ids; `message_id` should be populated.
* Datetimes are normalized to UTC.
* If you apply sender/recipient filters, they should be case-insensitive (normalize first).

---

### IMAP

IMAP support is typically used for **receiving** messages.

#### Credentials

You’ll need standard IMAP credentials:

* host (e.g., `imap.fastmail.com`)
* port (usually 993 for SSL)
* username
* password (or app password)
* folder (optional; often `INBOX`)

If you’re using env vars, you’ll typically have something like:

* `IMAP_HOST`
* `IMAP_PORT`
* `IMAP_USER`
* `IMAP_PASSWORD`
* `IMAP_SECURITY` (`SSL` / `STARTTLS` / `PLAINTEXT`)
* `IMAP_FOLDER`

#### Usage

```python
import asyncio

from trivialmessage.platform.imap import IMAPPlatform

imap = IMAPPlatform.from_env()

# Poll unread
unread = imap.get_unread()

# Listen (async generator)
async def main():
    async for msg in imap.listen():
        print(msg.from_email, msg.subject)

asyncio.run(main())
```

#### Platform-specific concerns

* IMAP is generally **receive-only**.

  * `send`, `reply`, `forward` should fail (unsupported) unless you separately configure SMTP and use a different platform for sending.
* Depending on server behavior, “fetching” can set flags unless you use BODY.PEEK semantics; implementations should avoid accidentally marking mail seen.
* IMAP `UID` exists but may not be stable across folders/servers; prefer `message_id` when possible.

---

### SMTP

SMTP is typically used for **sending** messages.

#### Credentials

You’ll need standard SMTP credentials:

* host (e.g., `smtp.fastmail.com`)
* port (commonly 465 for SSL or 587 for STARTTLS)
* username
* password (or app password)
* from address (optional override)

Common env vars:

* `SMTP_HOST`
* `SMTP_PORT`
* `SMTP_USER`
* `SMTP_PASSWORD`
* `SMTP_SECURITY` (`SSL` / `STARTTLS` / `PLAINTEXT`)
* `SMTP_EMAIL_FROM` (optional)

#### Usage

```python
from trivialmessage.platform.smtp import SMTPPlatform

smtp = SMTPPlatform.from_env()

sent = smtp.send(
    to="someone@example.com",
    subject="Hello",
    text="This is a test.",
)
print(sent.message_id)
```

#### Platform-specific concerns

* SMTP is generally **send-only**.

  * `get_unread` / `listen` should fail (unsupported).
* If you need bidirectional email, configure both an IMAP platform (receive) and SMTP platform (send), or use a single provider platform that supports both (e.g., Fastmail API).

---

### Protonmail (Bridge) (optional / legacy-compatible)

This platform exists only if you keep it around and install the extra.

#### Credentials

Protonmail typically requires running Protonmail Bridge locally/in-container.

This is complex and usually deployed as a dedicated variant. If you’re using it:

* ensure the Bridge is running and exposes IMAP + SMTP locally
* set the bridge IMAP/SMTP credentials (often generated by Bridge)

Typical env var contract (example):

* `BRIDGE_IMAP_USER`
* `BRIDGE_IMAP_PASSWORD`
* `BRIDGE_IMAP_HOST` (default `127.0.0.1`)
* `BRIDGE_IMAP_PORT` (default `1143`)
* `BRIDGE_IMAP_SECURITY` (`STARTTLS`/`SSL`/`PLAINTEXT`)
* and similar SMTP vars if sending

#### Usage

```python
import asyncio
from trivialmessage.platform.protonmail import ProtonmailPlatform

pm = ProtonmailPlatform.from_env()

# Receive
msgs = pm.get_unread()

# Send (via Bridge SMTP)
pm.send(to="someone@example.com", subject="Hi", text="...")

async def main():
    async for msg in pm.listen():
        print(msg.subject)

asyncio.run(main())
```

#### Platform-specific concerns

* Running Bridge is operationally heavy; treat it as a separate deployment.
* Bridge IMAP/SMTP are local-only; don’t expose those ports publicly.
* Message ids and header behavior depend on Bridge; your implementation should normalize to the same `Message` shape.

---

## Composing listeners

A common pattern is to listen to multiple platforms concurrently and yield messages as soon as they arrive from *any* source.

Desired usage:

```python
compose(
  fastmail.listen(filters=fs),
  protonmail.listen(filters=fs),
  whatsapp.listen(filters=fs),
)
```

The intended behavior:

* start all listeners concurrently,
* yield messages from whichever source produces next,
* do not block other sources,
* (error handling strategy is up to the caller / composition helper).

This repo expects a helper for that pattern (either provided here or in your application layer).

---

## Development

* Python: 3.10+ recommended
* Style: keep message payloads JSON-friendly
* Datetimes: always normalize to UTC-aware values
* Filters: normalize addresses for case-insensitive comparisons


