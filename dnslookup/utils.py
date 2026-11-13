"""Input normalisation helpers."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


class InvalidDomainError(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    """Turn user input ("https://Example.com/path", "example.com.") into "example.com".

    Internationalised names are converted to their IDNA (punycode) form.
    """
    value = raw.strip()
    if not value:
        raise InvalidDomainError("empty domain")

    if "://" in value:
        value = urlparse(value).hostname or ""
    else:
        value = value.split("/", 1)[0]
        if "@" in value:  # allow pasting an email address
            value = value.rsplit("@", 1)[1]
        value = value.split(":", 1)[0]  # drop :port

    value = value.rstrip(".").lower()
    if not value:
        raise InvalidDomainError(f"could not find a domain in {raw!r}")

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDomainError(f"invalid domain {raw!r}: {exc}") from exc

    if len(value) > 253:
        raise InvalidDomainError(f"domain too long: {raw!r}")
    for label in value.split("."):
        if not _LABEL_RE.match(label):
            raise InvalidDomainError(f"invalid domain {raw!r} (bad label {label!r})")
    return value


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False
