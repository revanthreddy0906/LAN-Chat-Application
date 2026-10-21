"""What the security features cost per operation on this machine (median of repeated runs).

    python3 bench/crypto_cost.py
"""
import os
import statistics
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import e2ee  # noqa: E402
from accounts import AccountStore  # noqa: E402


def timed(function, runs=15):
    samples = []
    for _ in range(runs):
        started = time.perf_counter()
        function()
        samples.append((time.perf_counter() - started) * 1000)
    return statistics.median(samples)


def main():
    accounts = AccountStore(os.path.join(tempfile.mkdtemp(), "c.db"))
    accounts.create_account("alice", "correct horse")
    print(f"# python {sys.version.split()[0]}, median of 15 runs")
    print(f"password check (scrypt n=2^14, r=8, p=1)      {timed(lambda: accounts.authenticate('alice', 'correct horse')):8.1f} ms")
    if not e2ee.AVAILABLE:
        print("end-to-end primitives: the cryptography package is not installed")
        return
    alice, bob = e2ee.Identity.generate(), e2ee.Identity.generate()
    bob_pub = bob.public()
    aad = e2ee.aad_for("text", "alice", "bob")
    text = b"x" * 200
    print(f"generate an identity (X25519 + Ed25519)       {timed(e2ee.Identity.generate):8.2f} ms")
    print(f"wrap keys with a passphrase (scrypt n=2^15)   {timed(lambda: e2ee.wrap(alice.secret_bytes(), 'pass phrase')):8.1f} ms")
    envelope = e2ee.seal(text, alice, bob_pub.dh, aad)
    print(f"seal a 200-byte message                       {timed(lambda: e2ee.seal(text, alice, bob_pub.dh, aad)):8.3f} ms")
    print(f"open it                                       {timed(lambda: e2ee.open_sealed(envelope, bob, alice.public(), aad)):8.3f} ms")
    print(f"safety number (5200 SHA-512 rounds)           {timed(lambda: e2ee.safety_number('alice', alice.public(), 'bob', bob_pub)):8.2f} ms")


if __name__ == "__main__":
    main()
