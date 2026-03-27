#!/usr/bin/env python3
# Copyright (c) 2026 KiteSurf Contributors — MIT License
# See LICENSE file for details.
"""
kite_crypto.py — AES-256-GCM encryption module for KiteSurf P2P channels.

Key derivation:
  - Dynamic pairing (Rendezvous): ECDH(X25519) → HKDF-SHA256 → AES-256
    The Rendezvous server never sees the shared secret — true end-to-end encryption.
  - Static nodes (pre-configured keys): secret → HKDF-SHA256 → AES-256

Packet format: [nonce:12][ciphertext+tag:N+16].
Falls back to unencrypted mode if the `cryptography` package is not installed.
"""

import hashlib
import ipaddress
import logging
import os
import struct
import threading
from typing import Optional, Tuple

log = logging.getLogger(name="kite-crypto")

# Try to import cryptography; graceful fallback on failure
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    log.warning(
        "[crypto] ⚠️  'cryptography' package not installed — "
        "P2P channels will be unencrypted. "
        "Install with: pip install cryptography"
    )


# ─────────────────────────── ECDH Key Exchange ─────────────────────────

def generate_ecdh_keypair() -> Tuple[bytes, bytes]:
    """Generate an X25519 ephemeral keypair for ECDH key exchange.

    Returns:
        (private_key_bytes, public_key_bytes) — both 32 bytes in raw format.
        Private key is returned as a mutable bytearray for secure erasure.

    The private key is kept only in memory; the public key is sent to the peer
    via the Rendezvous server (the server cannot compute the shared secret
    from the public keys alone).
    """
    if not HAS_CRYPTO:
        return b"", b""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = bytearray(private_key.private_bytes_raw())
    public_bytes = public_key.public_bytes_raw()
    return private_bytes, public_bytes


def ecdh_derive_secret(my_private_bytes: bytes, peer_public_bytes: bytes,
                       pair_id: str) -> str:
    """Perform X25519 ECDH and derive a hex-encoded shared secret.

    Steps:
      1. shared_point = X25519(my_private, peer_public)  — 32 bytes
      2. pair_secret = HKDF-SHA256(ikm=shared_point, salt=pair_id,
                                    info="kite-ecdh-v1")  — 32 bytes
      3. Return as a 64-character hex string (compatible with existing pair_secret format)

    Security:
      - Rendezvous can only see public keys → cannot compute shared_point
      - HKDF binds the output to a specific pair_id → channel isolation
      - Ephemeral keys → each pairing gets a unique shared secret

    Args:
        my_private_bytes: 32-byte raw X25519 private key
        peer_public_bytes: 32-byte raw X25519 public key from the peer
        pair_id: unique pairing/session identifier

    Returns:
        64-character hex string (256-bit pair_secret)
    """
    if not HAS_CRYPTO:
        return ""
    private_key = X25519PrivateKey.from_private_bytes(bytes(my_private_bytes))
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_point = bytearray(private_key.exchange(peer_public_key))  # 32 bytes

    # Derive pair_secret from raw ECDH output via HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=pair_id.encode("utf-8"),
        info=b"kite-ecdh-v1",
    )
    derived = hkdf.derive(bytes(shared_point))
    # Zeroize ephemeral shared point
    for i in range(len(shared_point)):
        shared_point[i] = 0
    # Zeroize private key material if mutable
    if isinstance(my_private_bytes, bytearray):
        for i in range(len(my_private_bytes)):
            my_private_bytes[i] = 0
    return derived.hex()  # 64-char hex — same format as legacy pair_secret


# ─────────────────────────── Key Derivation ───────────────────────────

def derive_channel_key(pair_secret: str, pair_id: str,
                       purpose: str = "kite-channel") -> bytes:
    """Derive a 256-bit AES key from the shared pair_secret.

    Uses HKDF-SHA256 with pair_id as salt and purpose as info label,
    ensuring different channels/purposes get different keys.

    Args:
        pair_secret: hex string (64 chars = 256 bits), from ECDH exchange
                     (or static key for pre-configured nodes)
        pair_id: unique session identifier (used as HKDF salt)
        purpose: key purpose label (e.g. "kite-udp", "kite-tcp")

    Returns:
        32-byte AES-256 key
    """
    if not HAS_CRYPTO:
        return b""

    # Convert secret to bytes: Rendezvous pair_secret is hex (64 chars),
    # but static node secrets may be arbitrary strings.
    try:
        secret_bytes = bytes.fromhex(pair_secret)
    except ValueError:
        secret_bytes = pair_secret.encode("utf-8")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=pair_id.encode("utf-8"),
        info=purpose.encode("utf-8"),
    )
    return hkdf.derive(secret_bytes)


# ─────────────────────────── Channel Cipher ───────────────────────────

class KiteChannelCipher:
    """AES-256-GCM cipher for a single P2P channel with forward secrecy.

    Security features:
        1. **Direction isolation**: Each side uses a different direction byte (0x01 / 0x02),
           determined by lexicographic order of node_ids, preventing nonce collision
           in both directions.
        2. **Forward secrecy (HKDF chain)**: Every ROTATION_INTERVAL messages,
           the send key is ratcheted forward via HKDF. Old key material is securely
           erased, so even if the current key is compromised, past messages cannot
           be decrypted.
        3. **Replay protection**: Each direction maintains a monotonically increasing counter.

    Nonce layout: [direction: 1] [counter: 8] [random: 3] = 12 bytes.
    The counter is *epoch-local* — reset to 0 after each key rotation,
    but the *global* counter (epoch * ROTATION_INTERVAL + local) is strictly monotonic,
    ensuring replay detection works across rotations.

    Key rotation (both sides rotate deterministically at the same counter):
        new_key = HKDF-SHA256(ikm=old_key, salt=pair_id, info="kite-ratchet-<epoch>")
        The old key is then zeroed out.

    Usage:
        cipher = KiteChannelCipher(pair_secret, pair_id,
                                   local_node_id="alice", peer_node_id="bob")
        encrypted = cipher.encrypt(plaintext)    # returns bytes
        plaintext = cipher.decrypt(encrypted)    # returns bytes or None
    """

    # Nonce layout: [direction byte(1)] [counter(8, big-endian)] [random(3)]
    NONCE_SIZE = 12
    TAG_SIZE = 16     # GCM tag appended by AESGCM
    HEADER_SIZE = NONCE_SIZE  # nonce is prepended to ciphertext

    DIR_FIRST = b"\x01"   # direction byte used by the lexicographically smaller node_id
    DIR_SECOND = b"\x02"  # direction byte used by the other side

    # ── Forward Secrecy ──
    # Rotate the AES key every N messages per direction.
    # 256 is a good balance: frequent enough for practical forward secrecy,
    # yet rare enough that the HKDF overhead (~1μs) is negligible (<0.4% at 1000 msg/s).
    ROTATION_INTERVAL = 256

    def __init__(self, pair_secret: str, pair_id: str,
                 purpose: str = "kite-channel",
                 local_node_id: str = "", peer_node_id: str = ""):
        """
        Args:
            pair_secret: Shared secret hex string (from ECDH or static config)
            pair_id: Unique pairing/session identifier (canonicalized, sorted)
            purpose: Key derivation purpose label
            local_node_id: Local node ID (used to determine direction bytes)
            peer_node_id: Remote node ID
        """
        self._pair_id = pair_id
        self._aad = pair_id.encode("utf-8")  # additional authenticated data
        self._enabled = bool(HAS_CRYPTO and pair_secret)

        # Determine direction bytes: lexicographically smaller node_id → 0x01, larger → 0x02
        if local_node_id and peer_node_id:
            if local_node_id < peer_node_id:
                self._send_dir = self.DIR_FIRST
                self._recv_dir = self.DIR_SECOND
            else:
                self._send_dir = self.DIR_SECOND
                self._recv_dir = self.DIR_FIRST
        else:
            # Backward compatibility for old callers (no node IDs provided, should not happen)
            self._send_dir = self.DIR_FIRST
            self._recv_dir = self.DIR_SECOND
            log.warning("[crypto] ⚠️  No node IDs provided — direction bytes may collide")

        if self._enabled:
            key = derive_channel_key(pair_secret, pair_id, purpose)
            self._send_key: bytearray = bytearray(key)  # mutable, for zeroing
            self._recv_key: bytearray = bytearray(key)   # same initial key, diverges after rotation
            self._send_aesgcm = AESGCM(bytes(self._send_key))
            self._recv_aesgcm = AESGCM(bytes(self._recv_key))

            self._send_counter = 0          # local counter within current send epoch
            self._send_epoch = 0            # number of send key rotations
            self._recv_max_counter = -1     # global counter for replay detection
            self._recv_epoch = 0            # current receive epoch
            self._recv_epoch_counter = -1   # local counter within current receive epoch
            # Sliding window for UDP out-of-order replay protection
            # Bitmap of 64 positions behind _recv_max_counter
            self._recv_window_size = 64
            self._recv_window_bitmap = 0    # bitmask: bit i = (max_counter - 1 - i) seen

            self._counter_lock = threading.Lock()
            log.info(f"[crypto] 🔒 Channel cipher initialized "
                     f"(pair={pair_id}, purpose={purpose}, "
                     f"send_dir=0x{self._send_dir.hex()}, recv_dir=0x{self._recv_dir.hex()}, "
                     f"rotation_interval={self.ROTATION_INTERVAL})")
        else:
            self._send_aesgcm = None
            self._recv_aesgcm = None
            self._send_key = bytearray()
            self._recv_key = bytearray()
            if pair_secret and not HAS_CRYPTO:
                log.warning(f"[crypto] ⚠️  Cipher disabled — 'cryptography' not installed")
            elif not pair_secret:
                log.warning(f"[crypto] ⚠️  Cipher disabled — no pair_secret")

    @property
    def enabled(self) -> bool:
        """Whether encryption is active."""
        return self._enabled

    # ── Key Rotation (Forward Secrecy) ────────────────────────────────

    @staticmethod
    def _zeroize(buf: bytearray):
        """Overwrite bytearray with zeros to erase key material."""
        for i in range(len(buf)):
            buf[i] = 0

    def _ratchet_key(self, current_key: bytearray, epoch: int) -> bytearray:
        """Derive the next epoch key via HKDF and zeroize the old key.

        new_key = HKDF(ikm=current_key, salt=pair_id, info="kite-ratchet-<epoch>")

        This is a one-way function: knowing new_key cannot reverse current_key,
        providing forward secrecy for all messages encrypted with current_key.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._aad,  # pair_id bytes — ensures channel binding
            info=f"kite-ratchet-{epoch}".encode("utf-8"),
        )
        new_key = bytearray(hkdf.derive(bytes(current_key)))
        self._zeroize(current_key)  # erase old key material
        return new_key

    def _maybe_rotate_send_key(self):
        """Rotate the send key if the rotation interval is reached.

        Called within _counter_lock, thread-safe.
        """
        if self._send_counter > 0 and self._send_counter % self.ROTATION_INTERVAL == 0:
            self._send_epoch += 1
            self._send_key = self._ratchet_key(self._send_key, self._send_epoch)
            self._send_aesgcm = AESGCM(bytes(self._send_key))
            self._send_counter = 0  # reset local counter for new epoch
            log.debug(f"[crypto] 🔄 Send key rotated → epoch {self._send_epoch}")

    def _maybe_rotate_recv_key(self, global_counter: int):
        """Rotate the receive key if the received message's global counter indicates the peer entered a new epoch.

        Both sides rotate at exactly the same global counter boundary,
        so this is deterministic and requires no signaling.
        """
        expected_epoch = global_counter // self.ROTATION_INTERVAL
        while self._recv_epoch < expected_epoch:
            self._recv_epoch += 1
            self._recv_key = self._ratchet_key(self._recv_key, self._recv_epoch)
            self._recv_aesgcm = AESGCM(bytes(self._recv_key))
            log.debug(f"[crypto] 🔄 Receive key rotated → epoch {self._recv_epoch}")

    # ── Encrypt / Decrypt ─────────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data using AES-256-GCM.

        Returns: [nonce(12)] [ciphertext + tag(16)]
        If encryption is disabled, returns the original plaintext.

        Automatically rotates keys every ROTATION_INTERVAL messages sent.
        """
        if not self._enabled:
            return plaintext

        nonce = self._make_send_nonce()
        ct_and_tag = self._send_aesgcm.encrypt(nonce, plaintext, self._aad)
        return nonce + ct_and_tag

    def decrypt(self, data: bytes) -> Optional[bytes]:
        """Decrypt and verify AES-256-GCM data.

        Args:
            data: [nonce(12)] [ciphertext + tag(16)]

        Returns:
            Decrypted plaintext, or None if verification fails.
            If encryption is disabled, returns the raw data.

        Automatically rotates the receive key when the peer's message counter crosses an epoch boundary.
        """
        if not self._enabled:
            return data

        if len(data) < self.NONCE_SIZE + self.TAG_SIZE:
            log.warning("[crypto] Packet too short to decrypt")
            return None

        nonce = data[:self.NONCE_SIZE]
        ct_and_tag = data[self.NONCE_SIZE:]

        # Direction check: received data must carry the *peer's* direction byte.
        # Reject packets carrying our send direction (reflection attack protection).
        if nonce[0:1] == self._send_dir:
            log.warning("[crypto] ⚠️  Received packet with our own send direction — "
                        "possible reflection attack, discarding")
            return None

        # Extract global counter and check for replay/rotation (sliding window)
        global_counter = self._extract_counter(nonce)
        if global_counter is not None:
            if global_counter > self._recv_max_counter:
                # New high — will be accepted; shift window after decrypt succeeds
                pass
            elif global_counter == self._recv_max_counter:
                log.warning(f"[crypto] ⚠️  Replay detected: counter={global_counter} "
                            f"== max={self._recv_max_counter}")
                return None
            else:
                # Check sliding window for slightly out-of-order packets
                diff = self._recv_max_counter - global_counter
                if diff > self._recv_window_size:
                    log.warning(f"[crypto] ⚠️  Replay/too-old: counter={global_counter} "
                                f"behind max={self._recv_max_counter} by {diff} "
                                f"(window={self._recv_window_size})")
                    return None
                bit_idx = diff - 1
                if self._recv_window_bitmap & (1 << bit_idx):
                    log.warning(f"[crypto] ⚠️  Replay detected: counter={global_counter} "
                                f"already seen in window")
                    return None

        # Rotate receive key if peer entered a new epoch
        if global_counter is not None:
            self._maybe_rotate_recv_key(global_counter)

        try:
            plaintext = self._recv_aesgcm.decrypt(nonce, ct_and_tag, self._aad)
            # Update replay window on successful decryption
            if global_counter is not None:
                if global_counter > self._recv_max_counter:
                    # Shift window: advance by (new - old) positions
                    shift = global_counter - self._recv_max_counter
                    if shift < self._recv_window_size:
                        self._recv_window_bitmap = (self._recv_window_bitmap << shift) & ((1 << self._recv_window_size) - 1)
                    else:
                        self._recv_window_bitmap = 0
                    self._recv_max_counter = global_counter
                else:
                    # Mark this counter as seen in the window
                    diff = self._recv_max_counter - global_counter
                    bit_idx = diff - 1
                    self._recv_window_bitmap |= (1 << bit_idx)
            return plaintext
        except Exception as e:
            log.warning(f"[crypto] ⚠️  Decryption failed: {e}")
            return None

    # ── Nonce Generation ──────────────────────────────────────────────

    def _make_send_nonce(self) -> bytes:
        """Generate a unique nonce: [send_dir] [global_counter(8)] [random(3)].

        The direction byte is determined at initialization based on node_id ordering.
        The counter encodes the *global* message sequence number
        (epoch * ROTATION_INTERVAL + local counter), ensuring monotonicity
        across key rotations.

        Key rotation is automatically triggered when the local counter reaches
        ROTATION_INTERVAL.
        """
        with self._counter_lock:
            # Check if key rotation is needed before using the current key
            self._maybe_rotate_send_key()
            global_counter = self._send_epoch * self.ROTATION_INTERVAL + self._send_counter
            self._send_counter += 1

        return (
            self._send_dir
            + struct.pack(">Q", global_counter)  # 8-byte big-endian
            + os.urandom(3)                      # 3-byte random entropy
        )

    @staticmethod
    def _extract_counter(nonce: bytes) -> Optional[int]:
        """Extract the 8-byte global counter from the nonce."""
        if len(nonce) < 9:
            return None
        return struct.unpack(">Q", nonce[1:9])[0]


# ─────────────────────── Encrypted WebSocket Wrapper ──────────────────

class EncryptedWebSocket:
    """Wraps a plain WebSocket with application-layer AES-256-GCM encryption.

    Used for direct TCP connections (LAN and public), where TLS certificates may not be available.
    Encryption uses pair_secret derived from ECDH key exchange (true end-to-end) or a static
    pre-shared key.

    Provides the same interface as a websockets WebSocket object:
        await ews.send(json_str)
        json_str = await ews.recv()

    Underlying WebSocket transports binary frames:
        [nonce(12)] [AES-GCM(json_bytes) + tag(16)]
    """

    def __init__(self, ws, cipher: KiteChannelCipher):
        self._ws = ws
        self._cipher = cipher
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def send(self, data: str):
        """Encrypt a JSON string and send as a binary frame."""
        if self._closed:
            raise RuntimeError("EncryptedWebSocket is closed")
        if self._cipher.enabled:
            plaintext = data.encode("utf-8")
            encrypted = self._cipher.encrypt(plaintext)
            await self._ws.send(encrypted)
        else:
            # Fallback: plaintext (no encryption available)
            await self._ws.send(data)

    async def recv(self) -> str:
        """Receive and decrypt a binary frame into a JSON string."""
        if self._closed:
            raise RuntimeError("EncryptedWebSocket is closed")
        raw = await self._ws.recv()
        if self._cipher.enabled:
            if isinstance(raw, str):
                # Reject plaintext on encrypted channel — possible downgrade attack
                log.warning("[crypto] ⚠️  Rejected unencrypted text frame on encrypted channel "
                            "— possible downgrade attack")
                raise RuntimeError("Plaintext frame received on encrypted channel — "
                                   "rejected to prevent downgrade attack")
            plaintext = self._cipher.decrypt(raw)
            if plaintext is None:
                raise RuntimeError("Decryption failed — possible tampering or wrong key")
            return plaintext.decode("utf-8")
        else:
            # Fallback: plaintext
            return raw if isinstance(raw, str) else raw.decode("utf-8")

    async def close(self):
        self._closed = True
        try:
            await self._ws.close()
        except Exception:
            pass

    @property
    def remote_address(self):
        return getattr(self._ws, 'remote_address', None)

    def __aiter__(self):
        return self

    async def __anext__(self) -> str:
        try:
            return await self.recv()
        except Exception:
            raise StopAsyncIteration


# ─────────────────── Self-Signed TLS Certificate Generator ────────────────

def generate_self_signed_cert(
    node_id: str,
    cert_path: str,
    key_path: str,
    days_valid: int = 365,
) -> bool:
    """Generate a self-signed TLS certificate for a Leader's Mini-Rendezvous.

    The certificate CN (Common Name) is set to the leader's node_id, providing
    a basic identity signal to connecting followers. Since followers know who
    the leader is (via election), they can optionally verify the CN matches
    the expected leader_id.

    Files are only generated if they don't already exist or if the existing
    cert has expired. This avoids regenerating on every leader election cycle.

    Args:
        node_id: Leader's node ID — used as the certificate CN.
        cert_path: File path to write the PEM-encoded certificate.
        key_path: File path to write the PEM-encoded RSA private key.
        days_valid: Certificate validity period in days (default 365).

    Returns:
        True if certificate files are ready (generated or already existed),
        False if the cryptography package is missing.
    """
    if not HAS_CRYPTO:
        log.warning("[crypto] Cannot generate self-signed cert — 'cryptography' not installed")
        return False

    import datetime
    from pathlib import Path

    cert_file = Path(cert_path)
    key_file = Path(key_path)

    # ── Check if existing cert is still valid ──
    if cert_file.exists() and key_file.exists():
        try:
            cert_pem = cert_file.read_bytes()
            existing_cert = x509.load_pem_x509_certificate(cert_pem)
            now = datetime.datetime.now(datetime.timezone.utc)
            if existing_cert.not_valid_after_utc > now:
                # Check CN matches current node_id
                cn_attrs = existing_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                existing_cn = cn_attrs[0].value if cn_attrs else ""
                if existing_cn == node_id:
                    log.info(f"[crypto] 🔒 Existing self-signed cert valid "
                             f"until {existing_cert.not_valid_after_utc.isoformat()} "
                             f"(CN={node_id})")
                    return True
                else:
                    log.info(f"[crypto] 🔄 Cert CN mismatch ({existing_cn} ≠ {node_id}) "
                             f"— regenerating")
            else:
                log.info(f"[crypto] 🔄 Cert expired — regenerating")
        except Exception as e:
            log.info(f"[crypto] 🔄 Cannot read existing cert ({e}) — regenerating")

    # ── Generate new RSA key + self-signed certificate ──
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, node_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KiteSurf Mini-RDV"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=days_valid))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName(node_id),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Ensure parent directories exist
        cert_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.parent.mkdir(parents=True, exist_ok=True)

        # Write private key (no encryption — this is a transient self-signed cert)
        key_file.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        # Restrict private key file permissions to owner-only (best-effort on Windows)
        try:
            key_file.chmod(0o600)
        except (OSError, NotImplementedError):
            pass  # chmod may not work on all platforms (e.g. Windows)

        # Write certificate
        cert_file.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )

        log.info(f"[crypto] 🔒 Self-signed TLS certificate generated "
                 f"(CN={node_id}, valid={days_valid}d, "
                 f"cert={cert_path}, key={key_path})")
        return True

    except Exception as e:
        log.error(f"[crypto] ❌ Failed to generate self-signed cert: {e}")
        return False
