"""Deciding whether a request on the webhook endpoint came from Telegram."""

from __future__ import annotations

import hmac
import ipaddress

from ..config import Config

#: Telegram's published webhook source ranges.
TELEGRAM_RANGES = ("149.154.160.0/20", "91.108.4.0/22")

#: The header Telegram sends the secret token in.
SECRET_HEADER = "X-Telegram-Bot-Api-Secret-Token"


class WebhookVerifier:
    """This is the most important check in the library.

    The webhook URL is public and unauthenticated, and what it accepts is an
    assertion of the form "this chat id is asking for a code". Without
    verification, anyone who learns the URL can post an update carrying a chat
    id and have the bot mint a code for whichever account that chat is linked
    to - and because the code then arrives in the real owner's chat, nothing in
    the application looks wrong.

    Telegram supports this directly: register the webhook with a secret_token
    and it sends that token in a header on every request.
    """

    def __init__(self, config: Config) -> None:
        self._config = config

    def accepts(self, header_value: str | None, remote_ip: str | None = None) -> bool:
        if not header_value:
            return False

        # compare_digest, so the time taken to reject does not reveal how much
        # of the secret was right.
        if not hmac.compare_digest(self._config.webhook_secret, header_value):
            return False

        if self._config.restrict_webhook_ips and not self.from_telegram(remote_ip):
            return False

        return True

    def from_telegram(self, remote_ip: str | None) -> bool:
        """Whether an address falls inside Telegram's published ranges.

        Only meaningful if ``remote_ip`` is the real peer. Behind a load
        balancer the peer is the proxy and the client address comes from a
        header the caller can set at will, which is why this is off by default
        and the secret token is not.
        """
        if not remote_ip:
            return False

        try:
            address = ipaddress.ip_address(remote_ip)
        except ValueError:
            return False

        return any(
            address in ipaddress.ip_network(cidr) for cidr in TELEGRAM_RANGES
        )
