#!/usr/bin/env python3
"""
signed_post.py — publish a DID note and post signed messages to technocore.chat

WHY THIS IS A SEPARATE FILE FROM agent_v2.py:

  agent_v2.py READS attacker-controlled text. This file HOLDS the signing key.
  They are deliberately never the same process. agent_v2.py has no import of
  did_identity and no way to reach a signature; this file never reads a room's
  contents into any decision it makes.

  Every command here is MANUAL and one-shot. There is no daemon, no loop, no
  auto-reply. A human types the text, a human confirms, then it signs and exits.
  Automating this would rebuild exactly the coupling the split exists to prevent.

Commands:
  python signed_post.py publish-did          # step 2: publish your DID note
  python signed_post.py say "your message"   # step 3: post a signed check-in
  python signed_post.py whoami               # show your public DID + note status

Prerequisites:
  python did_identity.py create              # step 1: generate the key (once)
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from urllib.parse import quote

import httpx

from did_identity import KEY_PATH, load_identity
# sanitize_text is the single-line sweep; the signature must cover the text
# AFTER it, because those are the bytes the server stores.
from agent_v2 import sanitize_text, outbound_gate, BASE_URL, USER_AGENT

TIMEOUT = 20.0


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=BASE_URL, timeout=TIMEOUT,
        headers={"User-Agent": USER_AGENT}, follow_redirects=False,
    )


def did_note_path(did: str) -> tuple[str, str]:
    """technocore shards DID notes: /kv/did-<first 2>/<remaining 14>, where the
    fingerprint is the first 16 lowercase hex chars of SHA-256(did string)."""
    fp = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    return f"did-{fp[:2]}", fp[2:]


def cmd_whoami() -> None:
    ident = load_identity()
    ns, key = did_note_path(ident.did)
    print(f"DID       : {ident.did}")
    print(f"note path : /kv/{ns}/{key}")
    with _client() as c:
        resp = c.get(f"/kv/{ns}/{key}")
        if resp.status_code == 200:
            print(f"note      : PUBLISHED -> {resp.text.strip()[:200]}")
        else:
            print(f"note      : not published yet (HTTP {resp.status_code})")
            print("            run: python signed_post.py publish-did")


def cmd_publish_did(label: str | None) -> None:
    """Step 2 of the onboarding: write a note at your DID's path so the network
    can see the identity exists. The note is an ORDINARY world-writable note —
    it proves nothing by itself; your signed messages are what prove key
    possession. Keep it minimal: no personal info, no links, no contact details."""
    ident = load_identity()
    ns, key = did_note_path(ident.did)

    # Keep the note boring on purpose. It is public and permanent-ish.
    value = sanitize_text(label or "technocore agent")
    if len(value) > 200:
        print("label too long (keep it under 200 chars)", file=sys.stderr)
        sys.exit(1)

    verdict = outbound_gate(value)
    if not verdict.allowed:
        print(f"BLOCKED by outbound gate: {verdict.reason}", file=sys.stderr)
        sys.exit(1)

    print(f"DID       : {ident.did}")
    print(f"note path : /kv/{ns}/{key}")
    print(f"value     : {verdict.text}")
    print()
    if input("publish this note? [y/N] ").strip().lower() != "y":
        print("aborted.")
        return

    with _client() as c:
        resp = c.get(f"/kv/{ns}/{key}/set/{quote(verdict.text, safe='')}")
    print(f"HTTP {resp.status_code}: {resp.text.strip()[:300]}")


def cmd_say(room: str, text: str) -> None:
    """Step 3: post a signed message. The nonce must exceed the last nonce this
    key used in this room; a millisecond clock satisfies that and never rewinds."""
    ident = load_identity()

    swept = sanitize_text(text)
    verdict = outbound_gate(swept)
    if not verdict.allowed:
        print(f"BLOCKED by outbound gate: {verdict.reason}", file=sys.stderr)
        print("Rewrite without URLs, addresses, hex/base58 blobs, or imperatives.",
              file=sys.stderr)
        sys.exit(1)

    # Sign the SWEPT text, not the raw text — otherwise it will not verify.
    swept = verdict.text
    nonce = int(time.time() * 1000)
    sig = ident.sign_say(room, nonce, swept)

    print(f"DID   : {ident.did}")
    print(f"room  : /r/{room}")
    print(f"nonce : {nonce}")
    print(f"text  : {swept}")
    print()
    print("This will be PUBLIC and attributable to your DID, effectively permanently.")
    if input("post it? [y/N] ").strip().lower() != "y":
        print("aborted.")
        return

    path = (f"/r/{room}/say-signed/{quote(ident.did, safe='')}/"
            f"{quote(sig, safe='')}/{nonce}/{quote(swept, safe='')}")
    with _client() as c:
        resp = c.get(path)

    print(f"HTTP {resp.status_code}")
    body = resp.text.strip()
    print(body[:500])
    if resp.status_code == 200:
        # The sequence number is what community trackers ask you to record.
        for line in body.splitlines():
            if ident.did[-8:] in line or "z6Mk" in line:
                print()
                print(f"your line: {line.strip()}")
                break
        print()
        print("Record the [seq] number from your line above if you want a "
              "citable pointer to this message.")


def main() -> None:
    ap = argparse.ArgumentParser(description="signed technocore posting (manual, one-shot)")
    ap.add_argument("--room", default="lobby")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("whoami")
    p_pub = sub.add_parser("publish-did")
    p_pub.add_argument("--label", default="technocore agent")
    p_say = sub.add_parser("say")
    p_say.add_argument("text")

    args = ap.parse_args()

    if not KEY_PATH.exists():
        print(f"No identity found at {KEY_PATH}.", file=sys.stderr)
        print("Run first: python did_identity.py create", file=sys.stderr)
        sys.exit(1)

    if args.command == "whoami":
        cmd_whoami()
    elif args.command == "publish-did":
        cmd_publish_did(args.label)
    elif args.command == "say":
        cmd_say(args.room, args.text)


if __name__ == "__main__":
    main()
