import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from dnslookup.resolver import DNSClient, QueryResult, Record


class FakeClient(DNSClient):
    """DNSClient backed by an in-memory zone: {(name, TYPE): [values]} or {(name, TYPE): "nxdomain"}."""

    def __init__(self, zone: dict):
        self.zone = {(k[0].lower().rstrip("."), k[1].upper()): v for k, v in zone.items()}
        self.calls: list[tuple[str, str]] = []

    @property
    def nameservers(self):
        return ["fake"]

    def query(self, name, rtype):
        rtype = rtype.upper()
        key = (name.lower().rstrip("."), rtype)
        self.calls.append(key)
        data = self.zone.get(key)
        if data is None:
            known = any(n == key[0] for n, _ in self.zone)
            return QueryResult(name, rtype, "noanswer" if known else "nxdomain")
        if isinstance(data, str):
            return QueryResult(name, rtype, data, error=data)
        recs = []
        for v in data:
            if isinstance(v, tuple):  # (priority, value)
                recs.append(Record(rtype, v[1], 300, v[0]))
            else:
                recs.append(Record(rtype, v, 300))
        return QueryResult(name, rtype, "ok", recs)

    def reverse(self, ip):
        return self.query(f"{ip}.rev", "PTR")


def rsa_key_b64(bits: int) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


@pytest.fixture(scope="session")
def key1024():
    return rsa_key_b64(1024)


@pytest.fixture(scope="session")
def key2048():
    return rsa_key_b64(2048)
