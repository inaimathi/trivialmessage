# tests/test_imap.py
"""
Tests for the IMAP adapter against a small in-memory fake IMAP4 connection
(imaplib itself is monkeypatched) rather than a real server, since spinning
up a real IMAP server is heavier than warranted here. The fake implements
just enough of the wire-level surface (login/select/uid search/uid
fetch/uid store/response/logout) to drive get_unread/get_recent/listen.

Run with: PYTHONPATH=src python3 -m unittest tests.test_imap -v
"""
import asyncio
import unittest
from email.message import EmailMessage
from unittest.mock import patch

import trivialmessage.imap as imap_mod


def _raw(subject, from_addr, to_addr, body, message_id="<x@example.com>"):
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = from_addr
    m["To"] = to_addr
    m["Message-ID"] = message_id
    m.set_content(body)
    return m.as_bytes()


class FakeMailbox:
    """Shared backing store behind however many fake connections get opened."""

    def __init__(self):
        # uid -> {"raw": bytes, "seen": bool}
        self.messages = {}
        self.uidvalidity = 1

    def uidnext(self):
        return (max(self.messages) + 1) if self.messages else 1


class FakeIMAP4:
    """Stands in for imaplib.IMAP4_SSL / imaplib.IMAP4."""

    def __init__(self, mailbox: FakeMailbox):
        self.mailbox = mailbox
        self.selected = False

    # -- connection lifecycle -------------------------------------------------
    def login(self, user, password):
        return ("OK", [b"Logged in"])

    def select(self, mailbox):
        self.selected = True
        return ("OK", [str(len(self.mailbox.messages)).encode()])

    def logout(self):
        return ("BYE", [b"Logging out"])

    def response(self, key):
        if key == "UIDVALIDITY":
            return ("OK", [str(self.mailbox.uidvalidity).encode()])
        if key == "UIDNEXT":
            return ("OK", [str(self.mailbox.uidnext()).encode()])
        return ("NO", [None])

    # -- uid commands -----------------------------------------------------
    def uid(self, command, *args):
        command = command.lower()
        if command == "search":
            return self._search(args)
        if command == "fetch":
            return self._fetch(args)
        if command == "store":
            return self._store(args)
        raise ValueError(f"unsupported uid command: {command}")

    def _search(self, args):
        # args = (None, *criteria_tokens)
        criteria = list(args[1:])
        uids = sorted(self.mailbox.messages.keys())

        if "UNSEEN" in criteria:
            uids = [u for u in uids if not self.mailbox.messages[u]["seen"]]

        if "UID" in criteria:
            idx = criteria.index("UID")
            rng = criteria[idx + 1]  # e.g. "3:*"
            start_s, _, end_s = rng.partition(":")
            start = int(start_s)
            end = None if end_s in ("", "*") else int(end_s)
            uids = [u for u in uids if u >= start and (end is None or u <= end)]

        data = " ".join(str(u) for u in uids).encode()
        return ("OK", [data])

    def _fetch(self, args):
        uid_str, section = args[0], args[1]
        uid = int(uid_str)
        entry = self.mailbox.messages.get(uid)
        if entry is None:
            return ("NO", [])

        # Only a real BODY.PEEK[] fetch avoids marking the message seen -
        # mirrors real IMAP server semantics closely enough to catch the
        # RFC822-vs-BODY.PEEK[] side-effect bug.
        if "PEEK" not in section.upper():
            entry["seen"] = True

        descriptor = f"{uid} ({section} {{{len(entry['raw'])}}}".encode()
        return ("OK", [(descriptor, entry["raw"])])

    def _store(self, args):
        uid_str, flag_op, flags = args
        uid = int(uid_str)
        if uid in self.mailbox.messages and "\\Seen" in flags:
            self.mailbox.messages[uid]["seen"] = True
        return ("OK", [b""])


class IMAPAdapterTests(unittest.TestCase):
    def setUp(self):
        self.mailbox = FakeMailbox()
        self.mailbox.messages[1] = {
            "raw": _raw(
                "Old news", "alice@example.com", "me@example.com", "already read"
            ),
            "seen": True,
        }
        self.mailbox.messages[2] = {
            "raw": _raw(
                "Unread thing", "bob@example.com", "me@example.com", "hi there"
            ),
            "seen": False,
        }

        self.platform = imap_mod.IMAPPlatform(
            imap_server="imap.example.com",
            username="me@example.com",
            password="hunter2",
        )

        patcher_ssl = patch.object(
            imap_mod.imaplib, "IMAP4_SSL", lambda *a, **kw: FakeIMAP4(self.mailbox)
        )
        patcher_plain = patch.object(
            imap_mod.imaplib, "IMAP4", lambda *a, **kw: FakeIMAP4(self.mailbox)
        )
        self.addCleanup(patcher_ssl.stop)
        self.addCleanup(patcher_plain.stop)
        patcher_ssl.start()
        patcher_plain.start()

    def test_get_unread_returns_only_unseen(self):
        msgs = self.platform.get_unread()
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].subject, "Unread thing")
        self.assertEqual(msgs[0].sender, "bob@example.com")

    def test_get_unread_does_not_mark_messages_seen(self):
        # Regression check for the RFC822-vs-BODY.PEEK[] side effect: a
        # plain (RFC822) fetch implicitly sets \Seen on most real IMAP
        # servers, which would silently break "get_unread" semantics.
        self.assertFalse(self.mailbox.messages[2]["seen"])
        self.platform.get_unread()
        self.assertFalse(self.mailbox.messages[2]["seen"])

    def test_get_recent_returns_all_sorted_and_limited(self):
        msgs = self.platform.get_recent(limit=1)
        self.assertEqual(len(msgs), 1)
        # Both messages were "sent" with essentially the same synthetic
        # timestamp (no Date header), so just confirm the limit is honored.
        self.assertIn(msgs[0].subject, {"Old news", "Unread thing"})

        msgs_all = self.platform.get_recent(limit=10)
        self.assertEqual(len(msgs_all), 2)

    def test_send_and_reply_are_unsupported(self):
        with self.assertRaises(NotImplementedError):
            self.platform.send("hi", to="x@example.com")
        with self.assertRaises(NotImplementedError):
            import datetime as dt

            from trivialmessage.common import Message

            fake_msg = Message(
                id="1",
                platform_type="imap",
                content="x",
                sender="a@example.com",
                timestamp=dt.datetime.now(dt.timezone.utc),
            )
            self.platform.reply(fake_msg, "reply")

    def test_listen_does_not_replay_existing_mail_but_catches_new_arrivals(self):
        """
        Both uid 1 and uid 2 already exist when the listener starts, so
        neither should be replayed. We then simulate a genuinely new
        message (uid 3) arriving between poll cycles by injecting it during
        the mocked `asyncio.sleep` call, and confirm the *next* poll picks
        it up - and nothing else.
        """
        # Speed up + hook the poll loop's `await asyncio.sleep(30)` so the
        # test doesn't take 30 real seconds and so we can inject a new
        # message right where "time passes" in the real world.
        call_count = {"n": 0}
        real_sleep = asyncio.sleep  # capture before patching - see below

        async def fake_sleep(_seconds):
            call_count["n"] += 1
            if call_count["n"] == 1:
                self.mailbox.messages[3] = {
                    "raw": _raw(
                        "Brand new",
                        "carol@example.com",
                        "me@example.com",
                        "just landed",
                    ),
                    "seen": False,
                }
            # NOTE: patching imap_mod.asyncio.sleep also patches this same
            # `asyncio` module as seen from this test file (it's the same
            # module object) - so we must call the captured original, not
            # `asyncio.sleep`, or this recurses into itself forever.
            await real_sleep(0)

        async def run():
            with patch.object(imap_mod.asyncio, "sleep", fake_sleep):
                gen = self.platform.listen()
                msg = await asyncio.wait_for(gen.__anext__(), timeout=5)
                self.assertEqual(msg.subject, "Brand new")
                self.assertEqual(msg.sender, "carol@example.com")
                await gen.aclose()

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
