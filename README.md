# TrivialMessage

A small, composable library that normalizes “messages” from different platforms (email today; others later) behind a single interface.

The goal is to make it easy to:

- fetch unread messages (polling),
- listen for new messages (async generators),
- send/reply/forward when supported,
- apply consistent filtering (sender/recipient/subject/time windows),
- keep datetimes normalized to UTC.

> Note: Several platforms (Gmail/Outlook) are intentionally **WIP** and may be stubbed or absent. Slack and WhatsApp were WIP but have since been fixed and covered by tests (see Changelog); Twilio (SMS + a deliberately partial Voice adapter) is new.

---

## Changelog

### Unreleased

- **Slack**: fixed `listen()`, which previously never yielded any messages.
  It imported `AsyncSocketModeClient` from a module that only exposes the
  abstract base class, and its event handler was written as an async
  *generator* even though `slack_sdk` only ever `await`s listener
  callbacks — so nothing it `yield`ed ever reached a caller, and events
  were never acknowledged (causing Slack to redeliver them). Fixed by
  bridging the callback to an internal `asyncio.Queue` and explicitly
  acking each event. Added the missing `send_async`/`reply_async`. See
  [Slack rationale](#slack) below.
- **WhatsApp**: fixed `listen()`, which had no `yield` anywhere in its
  body and was therefore a plain coroutine rather than an async
  generator — `async for msg in wa.listen()` raised a confusing
  `TypeError` before ever reaching the intended `NotImplementedError`.
  Added `send_async`/`reply_async` and surfaced HTTP error responses
  (4xx/5xx were previously parsed as if they'd succeeded). See
  [WhatsApp rationale](#whatsapp) below.
- **IMAP**: fixed a real data-integrity bug — message bodies were
  fetched with `(RFC822)`, which implicitly sets `\Seen` on most real
  IMAP servers, silently turning `get_unread()` into a mark-as-read
  operation. Switched to `BODY.PEEK[]`, which this module's own
  docstring already claimed (incorrectly) to be using.
- **Twilio**: new `trivialmessage.twilio` module with two classes -
  `TwilioSMSPlatform` (full `MessagePlatform` interface, including a
  real `get_recent` since Twilio's Messages resource is genuinely
  queryable) and `TwilioVoicePlatform` (deliberately partial - see
  [Twilio Voice rationale](#twilio-sms--voice) below). New `AudioContent`
  type for voice payloads.
- Added a `tests/` directory (previously the repo had none) covering
  Slack, WhatsApp, IMAP, SMTP, and Twilio with a mix of mocked and real
  local-server integration tests - see `unittest.sh`.

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

### Slack

Slack is a first-class chat platform using the Slack Web API for
send/reply/history and Socket Mode for real-time listening.

#### Credentials

* A bot token (`xoxb-...`) with `chat:write`, `channels:history`,
  `groups:history`, `im:history`, and `mpim:history` scopes.
* An app-level token (`xapp-...`) with the `connections:write` scope,
  required only for `listen()` (Socket Mode).

#### Usage

```python
import asyncio
from trivialmessage.slack import SlackPlatform

slack = SlackPlatform(bot_token="xoxb-...", app_token="xapp-...")

sent = slack.send("deploy finished", channel="C0123456")

async def main():
    async for msg in slack.listen():
        print(msg.sender, msg.content)

asyncio.run(main())
```

#### Rationale

`listen()` is implemented as a queue bridge rather than a direct
generator: Slack's `slack_sdk` Socket Mode client delivers events by
*calling a callback you register*, not by handing you an iterator, so
the adapter registers a small `async def message_handler(client, req)`
that acknowledges each event (`send_socket_mode_response`, required or
Slack will redeliver the event) and pushes a converted `Message` onto an
internal `asyncio.Queue`. `listen()` itself is just `while True: yield
await queue.get()`. This is the same shape SMS/Signal-style
webhook-driven platforms need (see the Twilio section), so it's worth
recognizing as a reusable pattern rather than a Slack-specific one.

`get_unread` has no true "unread" concept for a bot identity, so it
approximates by returning recent (last 24h by default) messages across
every channel the bot can see - this is expensive (one API call per
channel) and intended for occasional polling, not tight loops; prefer
`listen()` for anything latency-sensitive.

---

### WhatsApp

WhatsApp Business Cloud API support, send/reply only by design - see
below for why `get_unread`/`get_recent` are unsupported.

#### Credentials

* A phone number ID (used in the Graph API URL path, despite the
  constructor argument being named `phone_number`)
* A permanent or long-lived access token with `whatsapp_business_messaging`

#### Usage

```python
from trivialmessage.whatsapp import WhatsAppPlatform

wa = WhatsAppPlatform(phone_number="1234567890", access_token="...")
sent = wa.send("your order shipped", to="15550001234")
```

#### Rationale

`get_unread` and `get_recent` raise `NotImplementedError` deliberately,
not as a placeholder: the WhatsApp Cloud API has no endpoint to list or
query message history at all - it is a pure push (webhook) delivery
model with no server-side inbox to poll. Faking history by buffering
whatever `listen()` has seen would silently change the semantics (an
app-level cache masquerading as a platform capability), so this module
is honest about the gap instead.

`listen()` likewise raises `NotImplementedError`: receiving messages
requires a webhook endpoint that WhatsApp calls, which means running a
public HTTP server - something this library deliberately doesn't own
(see the Twilio SMS section for the pattern once that server exists in
your application). Because `listen()` has no `yield` anywhere in a
correct implementation of "not implemented yet", it still needs an
unreachable `yield` after the `raise` so Python treats it as an async
*generator* function - otherwise `async for msg in wa.listen()` fails
with a confusing `TypeError` before ever reaching the intended error
message.

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

### Twilio (SMS + Voice)

`trivialmessage.twilio` provides two separate classes on one shared
Twilio account: `TwilioSMSPlatform` (full `MessagePlatform` interface)
and `TwilioVoicePlatform` (send/reply only - a robocall notifier, not an
inbound call service).

#### Credentials

* `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` (shared by both classes)
* `TWILIO_FROM_NUMBER` or `TWILIO_MESSAGING_SERVICE_SID` for SMS
* `TWILIO_VOICE_FROM_NUMBER` for Voice

#### Usage

```python
import asyncio
from trivialmessage.twilio import TwilioSMSPlatform, TwilioVoicePlatform, AudioContent

sms = TwilioSMSPlatform.from_env()
sms.send("build failed on main", to="+15551234567")

# Inbound SMS arrives via a webhook you host - wire your framework's
# route to feed parsed messages into listen()'s queue:
#   sms.ingest(TwilioSMSPlatform.parse_webhook(request.form))
async def main():
    async for msg in sms.listen():
        print(msg.sender, msg.content)
asyncio.run(main())

voice = TwilioVoicePlatform.from_env()
voice.send(AudioContent(text="Production is down. Please acknowledge."), to="+15551234567")
```

#### Rationale

**SMS is a full adapter** because Twilio's Messages resource is
genuinely queryable (`GET /Messages.json` filtered by `To`/`From`/date),
unlike WhatsApp's Cloud API - so `get_recent` is a real implementation,
not a stub. `get_unread` still raises `NotImplementedError`: SMS itself
has no server-side read/unread state to query, regardless of provider.
`listen()` uses the same queue-bridge pattern as Slack, adapted for a
webhook instead of a socket: Twilio calls a webhook URL you configure
on your number for each inbound message, so the adapter exposes
`parse_webhook()` (pure, easily testable) and `ingest()` (pushes onto
the internal queue) for your web framework to call from its route
handler, rather than the library trying to own an HTTP server itself.

**Voice is intentionally partial.** The brief here was a way to notify
people of urgent developments by phone call - not a full inbound call
service, not a conversational agent. `TwilioVoicePlatform` therefore
does *not* subclass `MessagePlatform` (whose ABC would force stub
implementations of `listen`/`get_recent`/`get_unread` that would just be
lies) and only implements `send`/`send_async`/`reply`/`reply_async`.
Standing up webhook handling for inbound calls, call-status callbacks,
or DTMF acknowledgment is a real feature some day, but it's a
meaningfully bigger scope (a public server, a webhook contract, a
retry/escalation policy) than "place a call that speaks a message" -
better added deliberately later than half-implemented now.

`content` for voice is an `AudioContent` (`text` spoken via Twilio's
built-in `<Say>` TTS, or `url` for a pre-hosted audio file played via
`<Play>`) rather than a `str`, since a phone call has no text channel.
There's deliberately no field for raw audio bytes - Twilio's REST API
can only play from a URL it can fetch, not from bytes in a request
body, and this module isn't in the business of hosting files; upload
your own audio and pass the URL. TwiML generation (`_build_twiml`) is
kept as a pure function with no I/O specifically so it's cheap to unit
test exhaustively (escaping, voice selection, text-vs-url branching)
without touching the network.

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
