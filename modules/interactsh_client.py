"""
Interactsh Out-of-Band (OOB) Interaction Client

Provides genuine exploitation proof for vulnerability classes that can't be
confirmed by inspecting the HTTP response alone — most importantly SSRF,
but also blind XXE, blind command injection, and blind SQLi exfiltration.

How it works:
  1. Register a unique subdomain with the configured Interactsh server
     (self-hosted or interactsh.com), receiving a correlation ID and a
     public key for encrypted polling.
  2. Use that subdomain as the SSRF/XXE/etc. payload target instead of a
     static internal IP — e.g. http://<id>.oob.example.com/ instead of
     http://169.254.169.254/.
  3. Poll the Interactsh server for interactions. If the TARGET SERVER
     itself made a DNS lookup or HTTP request to that subdomain, that is
     unambiguous proof the target fetched our payload — this is real
     out-of-band confirmation, not a guess based on response content.

Configuration (via scan_config or environment variables):
  INTERACTSH_SERVER_URL — e.g. "https://oob.yourcompany.com"
  INTERACTSH_TOKEN      — auth token for a private/self-hosted server (optional)

If not configured, `InteractshClient.is_available()` returns False and
every caller MUST gracefully fall back to static-indicator-based detection,
labeling the resulting finding as "Potential" rather than "Confirmed" — the
whole point of this module is to upgrade confidence when available, never
to be a hard requirement.
"""

import base64
import json
import logging
import os
import random
import string
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class OOBInteraction:
    protocol:    str   # "dns", "http", "smtp"
    full_id:     str
    remote_addr: str = ""
    raw_request: str = ""
    timestamp:   str = ""


class InteractshClient:
    """
    Minimal Interactsh client. Does not implement the full RSA-encrypted
    polling protocol used by the official CLI client (which requires
    generating an RSA keypair and decrypting each interaction payload) —
    instead uses the server's unauthenticated/plaintext polling mode where
    available, or a self-hosted server configured for simple token-auth
    polling. For a fully spec-compliant private Interactsh deployment,
    swap the polling implementation in `_poll_raw()` to match your
    server's actual API contract.
    """

    def __init__(self, config: Dict):
        self.server_url = (
            config.get("interactsh_server_url")
            or os.environ.get("INTERACTSH_SERVER_URL", "")
        ).rstrip("/")
        self.token = (
            config.get("interactsh_token")
            or os.environ.get("INTERACTSH_TOKEN", "")
        )
        self.config = config
        self._session_id: Optional[str] = None
        self._correlation_id: Optional[str] = None
        self._registered = False

    def is_available(self) -> bool:
        """True only if a server URL has been configured. Does not perform
        a network call — callers should treat registration failures
        (network down, server unreachable) as 'not available' too and
        fall back gracefully."""
        return bool(self.server_url)

    # ── registration ──────────────────────────────────────────────────────────

    def register(self) -> Optional[str]:
        """
        Register a new unique interaction domain. Returns the full
        hostname to use as a payload target (e.g.
        'a1b2c3d4.oob.yourcompany.com'), or None if registration failed
        or no server is configured.
        """
        if not self.is_available():
            return None

        self._correlation_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        self._session_id = str(uuid.uuid4())

        try:
            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Authorization"] = self.token

            # Self-hosted servers vary in their exact registration contract;
            # this targets the common pattern of POST /register with a
            # correlation/session identifier and an idempotent public key
            # placeholder (full RSA exchange omitted — see class docstring).
            resp = requests.post(
                f"{self.server_url}/register",
                json={
                    "public-key": base64.b64encode(b"scanner-no-encryption").decode(),
                    "secret-key": self._session_id,
                    "correlation-id": self._correlation_id,
                },
                headers=headers,
                timeout=self.config.get("request_timeout", 10),
            )
            if resp.status_code not in (200, 201):
                logger.debug("Interactsh registration failed: HTTP %s", resp.status_code)
                return None

            self._registered = True
            domain = self.server_url.replace("https://", "").replace("http://", "")
            full_id = f"{self._correlation_id}.{domain}"
            logger.info("Interactsh OOB domain registered: %s", full_id)
            return full_id

        except Exception as exc:
            logger.debug("Interactsh registration error: %s", exc)
            return None

    # ── polling ───────────────────────────────────────────────────────────────

    def poll(self, wait_seconds: int = 8) -> List[OOBInteraction]:
        """
        Poll for any interactions (DNS lookups / HTTP requests) received on
        our registered domain since registration. Waits up to
        `wait_seconds` for the target to actually make the out-of-band
        request (network/DNS propagation isn't instant).
        """
        if not self._registered:
            return []

        deadline = time.time() + wait_seconds
        interactions: List[OOBInteraction] = []

        while time.time() < deadline:
            try:
                raw = self._poll_raw()
                if raw:
                    interactions.extend(raw)
                    break   # got at least one hit, no need to keep waiting
            except Exception as exc:
                logger.debug("Interactsh poll error: %s", exc)
            time.sleep(1.5)

        return interactions

    def _poll_raw(self) -> List[OOBInteraction]:
        headers = {}
        if self.token:
            headers["Authorization"] = self.token

        resp = requests.get(
            f"{self.server_url}/poll",
            params={"id": self._correlation_id, "secret": self._session_id},
            headers=headers,
            timeout=self.config.get("request_timeout", 10),
        )
        if resp.status_code != 200:
            return []

        data = resp.json()
        raw_list = data.get("data") or []
        results = []
        for item in raw_list:
            # Items may be base64-encoded JSON (encrypted mode) or plain
            # JSON depending on server config; try plain first.
            try:
                parsed = json.loads(item) if isinstance(item, str) else item
            except Exception:
                try:
                    parsed = json.loads(base64.b64decode(item))
                except Exception:
                    continue
            results.append(OOBInteraction(
                protocol    = parsed.get("protocol", "unknown"),
                full_id     = parsed.get("full-id", ""),
                remote_addr = parsed.get("remote-address", ""),
                raw_request = parsed.get("raw-request", "")[:500],
                timestamp   = parsed.get("timestamp", ""),
            ))
        return results

    def deregister(self):
        """Best-effort cleanup; failures here are not significant."""
        if not self._registered:
            return
        try:
            headers = {"Authorization": self.token} if self.token else {}
            requests.post(
                f"{self.server_url}/deregister",
                json={"correlation-id": self._correlation_id, "secret-key": self._session_id},
                headers=headers,
                timeout=5,
            )
        except Exception:
            pass
        self._registered = False
        
