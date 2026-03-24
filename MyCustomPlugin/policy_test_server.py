#!/usr/bin/env python3
"""Single-file HyConnect policy test server with Noise_NK over SSE.

This server mimics the localhost plugin endpoint used by Chromium:
  GET /streamPluginPolicy

It also serves a small control UI on:
  GET /

The Noise handshake and transport payloads match the browser integration:
  request header:  X-Noise-Handshake: <base64(client_handshake)>
  response header: X-Noise-Handshake: <base64(server_handshake)>
  SSE data payload: {"awcData":"<base64(noise_ciphertext)>"}

Inner plaintext JSON remains:
  {"policydata":"<base64(policy_json)>","loginStatus":true}
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import pathlib
import subprocess
import threading
import time
import tempfile
import webbrowser
from dataclasses import dataclass
from hashlib import sha256
from hmac import new as hmac_new
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


NOISE_PROTOCOL_NAME = b"Noise_NK_25519_ChaChaPoly_SHA256"
NOISE_HANDSHAKE_HEADER = "X-Noise-Handshake"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 16272
KEEPALIVE_INTERVAL_SECONDS = 15.0

# Keep these in sync with the hardcoded key material in the browser and Qt plugin.
SERVER_STATIC_PUBLIC_KEY_HEX = (
    "551f4f11d6ea7085f4d3258f46f77982bf170f60469c932c507dda3ae9f96f4d"
)
SERVER_STATIC_PRIVATE_KEY_HEX = (
    "0891788b41a01205a25bcbbea3b735e30077a3715d6f5da50cf0974e91de9a7f"
)

NOISE_C_PROTOCOL_SOURCES = [
    "src/backend/ref/cipher-aesgcm.c",
    "src/backend/ref/cipher-chachapoly.c",
    "src/backend/ref/dh-curve25519.c",
    "src/backend/ref/hash-blake2b.c",
    "src/backend/ref/hash-blake2s.c",
    "src/backend/ref/hash-sha256.c",
    "src/backend/ref/hash-sha512.c",
    "src/crypto/aes/rijndael-alg-fst.c",
    "src/crypto/blake2/blake2b.c",
    "src/crypto/blake2/blake2s.c",
    "src/crypto/chacha/chacha.c",
    "src/crypto/donna/poly1305-donna.c",
    "src/crypto/ed25519/ed25519.c",
    "src/crypto/ghash/ghash.c",
    "src/crypto/sha2/sha256.c",
    "src/crypto/sha2/sha512.c",
    "src/protocol/cipherstate.c",
    "src/protocol/dhstate.c",
    "src/protocol/errors.c",
    "src/protocol/handshakestate.c",
    "src/protocol/hashstate.c",
    "src/protocol/internal.c",
    "src/protocol/names.c",
    "src/protocol/patterns.c",
    "src/protocol/rand_os.c",
    "src/protocol/randstate.c",
    "src/protocol/symmetricstate.c",
    "src/protocol/util.c",
]

NOISE_C_HELPER_SOURCE = r"""
#include <noise.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    NoiseHandshakeState *handshake;
    NoiseCipherState *send_cipher;
    NoiseCipherState *receive_cipher;
    int ready;
} HyNoiseResponder;

static void hy_set_error(char **error, const char *message) {
    size_t len;
    if (!error)
        return;
    *error = 0;
    if (!message)
        return;
    len = strlen(message);
    *error = (char *)malloc(len + 1);
    if (!*error)
        return;
    memcpy(*error, message, len + 1);
}

static int hy_split_if_ready(HyNoiseResponder *session, char **error) {
    int action;
    if (!session || !session->handshake) {
        hy_set_error(error, "session is not initialized");
        return 0;
    }

    action = noise_handshakestate_get_action(session->handshake);
    if (action == NOISE_ACTION_SPLIT) {
        if (noise_handshakestate_split(
                session->handshake, &session->send_cipher,
                &session->receive_cipher) != NOISE_ERROR_NONE) {
            hy_set_error(error, "noise_handshakestate_split failed");
            return 0;
        }
        session->ready = 1;
        return 1;
    }

    return (action == NOISE_ACTION_READ_MESSAGE ||
            action == NOISE_ACTION_WRITE_MESSAGE ||
            action == NOISE_ACTION_COMPLETE);
}

void hy_noise_free_error(char *error) {
    if (error)
        free(error);
}

void *hy_noise_responder_new(const uint8_t *private_key, size_t private_key_len, char **error) {
    HyNoiseResponder *session;
    NoiseDHState *local_static;
    if (!private_key || private_key_len != 32) {
        hy_set_error(error, "private key must be 32 bytes");
        return 0;
    }

    session = (HyNoiseResponder *)calloc(1, sizeof(HyNoiseResponder));
    if (!session) {
        hy_set_error(error, "calloc failed");
        return 0;
    }

    if (noise_handshakestate_new_by_name(
            &session->handshake,
            "Noise_NK_25519_ChaChaPoly_SHA256",
            NOISE_ROLE_RESPONDER) != NOISE_ERROR_NONE) {
        hy_set_error(error, "noise_handshakestate_new_by_name failed");
        free(session);
        return 0;
    }

    local_static = noise_handshakestate_get_local_keypair_dh(session->handshake);
    if (!local_static ||
        noise_dhstate_set_keypair_private(local_static, private_key, private_key_len) != NOISE_ERROR_NONE ||
        noise_handshakestate_start(session->handshake) != NOISE_ERROR_NONE) {
        hy_set_error(error, "failed to initialize responder static key");
        noise_handshakestate_free(session->handshake);
        free(session);
        return 0;
    }

    return session;
}

void hy_noise_responder_free(void *ptr) {
    HyNoiseResponder *session = (HyNoiseResponder *)ptr;
    if (!session)
        return;
    if (session->send_cipher)
        noise_cipherstate_free(session->send_cipher);
    if (session->receive_cipher)
        noise_cipherstate_free(session->receive_cipher);
    if (session->handshake)
        noise_handshakestate_free(session->handshake);
    free(session);
}

int hy_noise_responder_read_handshake(
        void *ptr, const uint8_t *message, size_t message_len, char **error) {
    HyNoiseResponder *session = (HyNoiseResponder *)ptr;
    NoiseBuffer buffer;
    uint8_t *copy;
    if (!session || !session->handshake) {
        hy_set_error(error, "session not ready for read");
        return 0;
    }
    if (noise_handshakestate_get_action(session->handshake) != NOISE_ACTION_READ_MESSAGE) {
        hy_set_error(error, "unexpected handshake action before read");
        return 0;
    }
    copy = (uint8_t *)malloc(message_len);
    if (!copy) {
        hy_set_error(error, "malloc failed");
        return 0;
    }
    memcpy(copy, message, message_len);
    noise_buffer_set_input(buffer, copy, message_len);
    if (noise_handshakestate_read_message(session->handshake, &buffer, 0) != NOISE_ERROR_NONE) {
        free(copy);
        hy_set_error(error, "noise_handshakestate_read_message failed");
        return 0;
    }
    free(copy);
    return hy_split_if_ready(session, error);
}

int hy_noise_responder_write_handshake(
        void *ptr, uint8_t *out, size_t out_cap, size_t *out_len, char **error) {
    HyNoiseResponder *session = (HyNoiseResponder *)ptr;
    NoiseBuffer buffer;
    if (!session || !session->handshake) {
        hy_set_error(error, "session not ready for write");
        return 0;
    }
    if (noise_handshakestate_get_action(session->handshake) != NOISE_ACTION_WRITE_MESSAGE) {
        hy_set_error(error, "unexpected handshake action before write");
        return 0;
    }
    noise_buffer_set_output(buffer, out, out_cap);
    if (noise_handshakestate_write_message(session->handshake, &buffer, 0) != NOISE_ERROR_NONE) {
        hy_set_error(error, "noise_handshakestate_write_message failed");
        return 0;
    }
    if (out_len)
        *out_len = buffer.size;
    return hy_split_if_ready(session, error);
}

int hy_noise_responder_is_ready(void *ptr) {
    HyNoiseResponder *session = (HyNoiseResponder *)ptr;
    return session && session->ready;
}

int hy_noise_responder_encrypt(
        void *ptr, const uint8_t *plaintext, size_t plaintext_len,
        uint8_t *out, size_t out_cap, size_t *out_len, char **error) {
    HyNoiseResponder *session = (HyNoiseResponder *)ptr;
    NoiseBuffer buffer;
    uint8_t *copy;
    size_t needed;
    if (!session || !session->ready || !session->send_cipher) {
        hy_set_error(error, "session is not ready for encryption");
        return 0;
    }
    needed = plaintext_len + noise_cipherstate_get_mac_length(session->send_cipher);
    if (out_cap < needed) {
        hy_set_error(error, "output buffer too small");
        return 0;
    }
    copy = (uint8_t *)malloc(needed);
    if (!copy) {
        hy_set_error(error, "malloc failed");
        return 0;
    }
    memcpy(copy, plaintext, plaintext_len);
    noise_buffer_set_inout(buffer, copy, plaintext_len, needed);
    if (noise_cipherstate_encrypt(session->send_cipher, &buffer) != NOISE_ERROR_NONE) {
        free(copy);
        hy_set_error(error, "noise_cipherstate_encrypt failed");
        return 0;
    }
    memcpy(out, copy, buffer.size);
    if (out_len)
        *out_len = buffer.size;
    free(copy);
    return 1;
}
"""


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def hash256(data: bytes) -> bytes:
    return sha256(data).digest()


def hkdf(chaining_key: bytes, input_key_material: bytes, count: int) -> List[bytes]:
    temp_key = hmac_new(chaining_key, input_key_material, sha256).digest()
    outputs: List[bytes] = []
    previous = b""
    for index in range(1, count + 1):
        previous = hmac_new(temp_key, previous + bytes([index]), sha256).digest()
        outputs.append(previous)
    return outputs


def noise_nonce(counter: int) -> bytes:
    return b"\x00\x00\x00\x00" + counter.to_bytes(8, "little")


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def _project_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


class NoiseCLibrary:
    _library = None
    _lock = threading.Lock()

    @classmethod
    def load(cls):
        with cls._lock:
            if cls._library is not None:
                return cls._library

            root = _project_root()
            noise_dir = root / "third_party" / "noise-c"
            build_dir = pathlib.Path(tempfile.gettempdir()) / "hyconnect_noise_c"
            build_dir.mkdir(parents=True, exist_ok=True)
            helper_c = build_dir / "hyconnect_noise_helper.c"
            dylib = build_dir / "libhyconnect_noise_helper.dylib"
            helper_c.write_text(NOISE_C_HELPER_SOURCE)

            sources = [str(helper_c)]
            sources.extend(str(noise_dir / rel) for rel in NOISE_C_PROTOCOL_SOURCES)
            command = [
                "clang",
                "-dynamiclib",
                "-O2",
                "-fPIC",
                "-Wno-expansion-to-defined",
                "-DED25519_CUSTOMHASH",
                "-DED25519_CUSTOMRANDOM",
                "-I",
                str(noise_dir / "include"),
                "-I",
                str(noise_dir / "src"),
                "-I",
                str(noise_dir / "src" / "protocol"),
                "-I",
                str(noise_dir / "src" / "keys"),
                "-o",
                str(dylib),
            ]
            command.extend(sources)

            rebuild = not dylib.exists()
            if not rebuild:
                dylib_mtime = dylib.stat().st_mtime
                inputs = [helper_c]
                inputs.extend(noise_dir / rel for rel in NOISE_C_PROTOCOL_SOURCES)
                rebuild = any(path.stat().st_mtime > dylib_mtime for path in inputs)

            if rebuild:
                log("Building native noise-c helper for Python test server")
                subprocess.run(command, check=True)

            lib = ctypes.CDLL(str(dylib))
            lib.hy_noise_responder_new.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_char_p),
            ]
            lib.hy_noise_responder_new.restype = ctypes.c_void_p
            lib.hy_noise_responder_free.argtypes = [ctypes.c_void_p]
            lib.hy_noise_responder_free.restype = None
            lib.hy_noise_responder_read_handshake.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_char_p),
            ]
            lib.hy_noise_responder_read_handshake.restype = ctypes.c_int
            lib.hy_noise_responder_write_handshake.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t),
                ctypes.POINTER(ctypes.c_char_p),
            ]
            lib.hy_noise_responder_write_handshake.restype = ctypes.c_int
            lib.hy_noise_responder_is_ready.argtypes = [ctypes.c_void_p]
            lib.hy_noise_responder_is_ready.restype = ctypes.c_int
            lib.hy_noise_responder_encrypt.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t),
                ctypes.POINTER(ctypes.c_char_p),
            ]
            lib.hy_noise_responder_encrypt.restype = ctypes.c_int
            lib.hy_noise_free_error.argtypes = [ctypes.c_char_p]
            lib.hy_noise_free_error.restype = None

            cls._library = lib
            return cls._library


class NativeNoiseResponderSession:
    def __init__(self, responder_private_key: bytes) -> None:
        self._lib = NoiseCLibrary.load()
        error = ctypes.c_char_p()
        key_buffer = ctypes.create_string_buffer(responder_private_key, len(responder_private_key))
        self._ptr = self._lib.hy_noise_responder_new(
            key_buffer,
            len(responder_private_key),
            ctypes.byref(error),
        )
        if not self._ptr:
            raise RuntimeError(self._take_error(error))

    def _take_error(self, error: ctypes.c_char_p) -> str:
        if not error.value:
            return "unknown noise-c error"
        message = error.value.decode("utf-8", errors="replace")
        self._lib.hy_noise_free_error(error.value)
        return message

    @property
    def ready(self) -> bool:
        return bool(self._lib.hy_noise_responder_is_ready(self._ptr))

    def read_handshake_message(self, message: bytes) -> None:
        error = ctypes.c_char_p()
        message_buffer = ctypes.create_string_buffer(message, len(message))
        if not self._lib.hy_noise_responder_read_handshake(
            self._ptr,
            message_buffer,
            len(message),
            ctypes.byref(error),
        ):
            raise RuntimeError(self._take_error(error))

    def write_handshake_message(self) -> bytes:
        output = ctypes.create_string_buffer(512)
        output_len = ctypes.c_size_t()
        error = ctypes.c_char_p()
        if not self._lib.hy_noise_responder_write_handshake(
            self._ptr,
            output,
            len(output),
            ctypes.byref(output_len),
            ctypes.byref(error),
        ):
            raise RuntimeError(self._take_error(error))
        return output.raw[: output_len.value]

    def encrypt(self, plaintext: bytes) -> bytes:
        output = ctypes.create_string_buffer(len(plaintext) + 32)
        output_len = ctypes.c_size_t()
        error = ctypes.c_char_p()
        plaintext_buffer = ctypes.create_string_buffer(plaintext, len(plaintext))
        if not self._lib.hy_noise_responder_encrypt(
            self._ptr,
            plaintext_buffer,
            len(plaintext),
            output,
            len(output),
            ctypes.byref(output_len),
            ctypes.byref(error),
        ):
            raise RuntimeError(self._take_error(error))
        return output.raw[: output_len.value]

    def close(self) -> None:
        if getattr(self, "_ptr", None):
            self._lib.hy_noise_responder_free(self._ptr)
            self._ptr = None

    def __del__(self) -> None:
        self.close()


class CipherState:
    def __init__(self, key: Optional[bytes] = None) -> None:
        self._key = key
        self._nonce = 0

    def has_key(self) -> bool:
        return self._key is not None

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if not self._key:
            return plaintext
        cipher = ChaCha20Poly1305(self._key)
        ciphertext = cipher.encrypt(noise_nonce(self._nonce), plaintext, ad)
        self._nonce += 1
        return ciphertext

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if not self._key:
            return ciphertext
        cipher = ChaCha20Poly1305(self._key)
        plaintext = cipher.decrypt(noise_nonce(self._nonce), ciphertext, ad)
        self._nonce += 1
        return plaintext


class SymmetricState:
    def __init__(self) -> None:
        protocol_hash = (
            NOISE_PROTOCOL_NAME
            if len(NOISE_PROTOCOL_NAME) <= 32
            else hash256(NOISE_PROTOCOL_NAME)
        )
        self.ck = protocol_hash
        self.h = protocol_hash
        self.cipher = CipherState()

    def mix_hash(self, data: bytes) -> None:
        self.h = hash256(self.h + data)

    def mix_key(self, input_key_material: bytes) -> None:
        self.ck, temp_k = hkdf(self.ck, input_key_material, 2)
        self.cipher = CipherState(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> tuple[CipherState, CipherState]:
        temp_k1, temp_k2 = hkdf(self.ck, b"", 2)
        return CipherState(temp_k1), CipherState(temp_k2)


class NoiseNKResponderSession:
    """Responder side of Noise_NK_25519_ChaChaPoly_SHA256."""

    def __init__(self, responder_private_key: bytes, responder_public_key: bytes) -> None:
        self._symmetric = SymmetricState()
        self._symmetric.mix_hash(responder_public_key)

        self._responder_private = x25519.X25519PrivateKey.from_private_bytes(
            responder_private_key
        )
        self._initiator_ephemeral: Optional[x25519.X25519PublicKey] = None
        self._send_cipher: Optional[CipherState] = None
        self._receive_cipher: Optional[CipherState] = None
        self._ready = False

    @property
    def ready(self) -> bool:
        return self._ready

    def read_handshake_message(self, message: bytes) -> None:
        if len(message) < 32 + 16:
            raise ValueError("client handshake is too short")

        initiator_ephemeral_public = message[:32]
        encrypted_payload = message[32:]

        self._initiator_ephemeral = x25519.X25519PublicKey.from_public_bytes(
            initiator_ephemeral_public
        )
        self._symmetric.mix_hash(initiator_ephemeral_public)

        dh_es = self._responder_private.exchange(self._initiator_ephemeral)
        self._symmetric.mix_key(dh_es)

        payload = self._symmetric.decrypt_and_hash(encrypted_payload)
        if payload != b"":
            raise ValueError("unexpected initiator handshake payload")

    def write_handshake_message(self) -> bytes:
        if self._initiator_ephemeral is None:
            raise ValueError("handshake read must happen first")

        responder_ephemeral_private = x25519.X25519PrivateKey.generate()
        responder_ephemeral_public = responder_ephemeral_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        self._symmetric.mix_hash(responder_ephemeral_public)

        dh_ee = responder_ephemeral_private.exchange(self._initiator_ephemeral)
        self._symmetric.mix_key(dh_ee)

        encrypted_payload = self._symmetric.encrypt_and_hash(b"")
        self._send_cipher, self._receive_cipher = self._symmetric.split()
        self._ready = True
        return responder_ephemeral_public + encrypted_payload

    def encrypt(self, plaintext: bytes) -> bytes:
        if not self._ready or self._send_cipher is None:
            raise ValueError("noise session is not ready")
        return self._send_cipher.encrypt_with_ad(b"", plaintext)


@dataclass
class PolicyState:
    login_status: bool
    policy_json_text: str

    def normalized_policy_json(self) -> str:
        parsed = json.loads(self.policy_json_text or "{}")
        return json.dumps(parsed, separators=(",", ":"), sort_keys=True)

    def to_inner_json_bytes(self) -> bytes:
        policy_data_b64 = b64encode(self.normalized_policy_json().encode("utf-8"))
        return json.dumps(
            {"policydata": policy_data_b64, "loginStatus": self.login_status},
            separators=(",", ":"),
        ).encode("utf-8")


@dataclass
class LastStreamedEvent:
    event_id: int
    source: str
    login_status: bool
    effective_policy_json: str
    inner_payload_json: str
    awc_data_b64: str
    plaintext_bytes: int
    ciphertext_bytes: int


class SharedState:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._policy_state = PolicyState(login_status=True, policy_json_text="{}")
        self._subscribers: List["Subscriber"] = []
        self._event_counter = 0
        self._last_streamed_event: Optional[LastStreamedEvent] = None

    def get_state(self) -> PolicyState:
        with self._lock:
            return PolicyState(
                login_status=self._policy_state.login_status,
                policy_json_text=self._policy_state.policy_json_text,
            )

    def set_state(self, login_status: bool, policy_json_text: str) -> PolicyState:
        with self._lock:
            parsed = json.loads(policy_json_text or "{}")
            normalized = json.dumps(parsed, indent=2, sort_keys=True)
            self._policy_state = PolicyState(login_status=login_status, policy_json_text=normalized)
            return self.get_state()

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def next_event_id(self) -> int:
        with self._lock:
            self._event_counter += 1
            return self._event_counter

    def set_last_streamed_event(self, event: LastStreamedEvent) -> None:
        with self._lock:
            self._last_streamed_event = event

    def last_streamed_event(self) -> Optional[LastStreamedEvent]:
        with self._lock:
            return self._last_streamed_event

    def add_subscriber(self, subscriber: "Subscriber") -> None:
        with self._lock:
            self._subscribers.append(subscriber)
            count = len(self._subscribers)
        log(f"SSE subscriber added, active={count}")

    def remove_subscriber(self, subscriber: "Subscriber") -> None:
        with self._lock:
            if subscriber in self._subscribers:
                self._subscribers.remove(subscriber)
            count = len(self._subscribers)
        log(f"SSE subscriber removed, active={count}")

    def broadcast(self, source: str = "update") -> None:
        with self._lock:
            state = self.get_state()
            subscribers = list(self._subscribers)
        log(
            "Broadcasting policy update to "
            f"{len(subscribers)} subscriber(s), loginStatus={state.login_status}, source={source}, "
            f"effective_policy={state.normalized_policy_json()}"
        )
        for subscriber in subscribers:
            subscriber.send_state(state, source=source)

    def keepalive(self) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            subscriber.send_keepalive()


class Subscriber:
    def __init__(self, handler: "PolicyTestHandler", session: NoiseNKResponderSession) -> None:
        self._handler = handler
        self._session = session
        self._lock = threading.Lock()
        self._closed = False

    def send_keepalive(self) -> None:
        log("Sending SSE keepalive")
        self._write_raw(b": keepalive\n\n")

    def send_state(self, state: PolicyState, source: str = "stream") -> None:
        try:
            plaintext = state.to_inner_json_bytes()
            ciphertext = self._session.encrypt(plaintext)
            awc_data_b64 = b64encode(ciphertext)
            payload = json.dumps({"awcData": awc_data_b64}, separators=(",", ":"))
            event_id = SHARED_STATE.next_event_id()
            inner_payload_json = plaintext.decode("utf-8", errors="replace")
            effective_policy_json = state.normalized_policy_json()
            SHARED_STATE.set_last_streamed_event(
                LastStreamedEvent(
                    event_id=event_id,
                    source=source,
                    login_status=state.login_status,
                    effective_policy_json=effective_policy_json,
                    inner_payload_json=inner_payload_json,
                    awc_data_b64=awc_data_b64,
                    plaintext_bytes=len(plaintext),
                    ciphertext_bytes=len(ciphertext),
                )
            )
            log(
                f"STREAM event_id={event_id} source={source} "
                f"loginStatus={state.login_status} "
                f"effective_policy={effective_policy_json} "
                f"inner_payload={inner_payload_json} "
                f"awcData_b64={awc_data_b64}"
            )
            self._write_raw(f"data: {payload}\n\n".encode("utf-8"))
        except Exception as exc:
            log(f"Failed to send encrypted policy event: {exc}")
            self.close()

    def _write_raw(self, data: bytes) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._handler.wfile.write(data)
                self._handler.wfile.flush()
            except Exception as exc:
                log(f"SSE socket write failed: {exc}")
                self.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            close_fn = getattr(self._session, "close", None)
            if callable(close_fn):
                close_fn()
        SHARED_STATE.remove_subscriber(self)


SHARED_STATE = SharedState()
RESPONDER_PRIVATE_KEY = bytes.fromhex(SERVER_STATIC_PRIVATE_KEY_HEX)
RESPONDER_PUBLIC_KEY = bytes.fromhex(SERVER_STATIC_PUBLIC_KEY_HEX)


def build_html(state: PolicyState, subscriber_count: int) -> str:
    checked = "checked" if state.login_status else ""
    policy_text = state.policy_json_text
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HyConnect Policy Test Server</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f3efe6;
      --panel: #fffaf1;
      --ink: #1f2a37;
      --accent: #0f766e;
      --accent-2: #b45309;
      --line: #d6d3c7;
    }}
    body {{
      margin: 0;
      font-family: "Iowan Old Style", "Palatino Linotype", serif;
      background:
        radial-gradient(circle at top left, rgba(180, 83, 9, 0.12), transparent 30%),
        linear-gradient(180deg, #f8f4ec 0%, var(--bg) 100%);
      color: var(--ink);
    }}
    .wrap {{
      max-width: 980px;
      margin: 40px auto;
      padding: 0 20px 40px;
    }}
    .hero {{
      display: grid;
      gap: 16px;
      margin-bottom: 24px;
    }}
    .hero h1 {{
      margin: 0;
      font-size: clamp(2rem, 4vw, 3.5rem);
      line-height: 0.95;
    }}
    .hero p {{
      margin: 0;
      max-width: 700px;
      font-size: 1.05rem;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 20px;
      box-shadow: 0 18px 50px rgba(31, 42, 55, 0.07);
    }}
    .meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 18px;
      font-family: "Menlo", "SFMono-Regular", monospace;
      font-size: 0.9rem;
    }}
    .pill {{
      padding: 8px 10px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: #fff;
    }}
    form {{
      display: grid;
      gap: 16px;
    }}
    textarea {{
      min-height: 340px;
      width: 100%;
      resize: vertical;
      border-radius: 14px;
      border: 1px solid var(--line);
      padding: 14px;
      font: 14px/1.5 "Menlo", "SFMono-Regular", monospace;
      background: #fff;
      box-sizing: border-box;
    }}
    .row {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 16px;
    }}
    .policy-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }}
    .policy-card {{
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 12px 14px;
      background: #fff;
    }}
    .policy-card label {{
      display: flex;
      gap: 10px;
      align-items: flex-start;
    }}
    .policy-card strong {{
      display: block;
      margin-bottom: 4px;
    }}
    button {{
      appearance: none;
      border: 0;
      border-radius: 999px;
      padding: 12px 18px;
      font: inherit;
      color: #fff;
      background: linear-gradient(135deg, var(--accent), #0b5c56);
      cursor: pointer;
    }}
    .secondary {{
      background: linear-gradient(135deg, var(--accent-2), #92400e);
    }}
    .note {{
      font-size: 0.95rem;
      opacity: 0.8;
    }}
    .preview-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 14px;
    }}
    .preview-card {{
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
      background: #fff;
    }}
    .preview-card pre {{
      margin: 8px 0 0;
      white-space: pre-wrap;
      word-break: break-word;
      font: 12px/1.45 "Menlo", "SFMono-Regular", monospace;
    }}
    #flash {{
      min-height: 1.5em;
      font-family: "Menlo", "SFMono-Regular", monospace;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>HyConnect Policy Test Server</h1>
      <p>Control localhost policy SSE state, keep the browser handshake flow intact, and push live encrypted policy updates without changing the Chromium-side JSON parsing.</p>
    </section>
    <section class="panel">
      <div class="meta">
        <div class="pill">Endpoint: http://127.0.0.1:{SERVER_PORT}/streamPluginPolicy</div>
        <div class="pill">Subscribers: <span id="subscribers">{subscriber_count}</span></div>
        <div class="pill">Noise: NK / ChaChaPoly / SHA256</div>
      </div>
      <form id="control-form">
        <label class="row">
          <input type="checkbox" id="loginStatus" {checked}>
          <span>Login status enabled</span>
        </label>
        <div>
          <div class="note">Quick policy toggles</div>
          <div class="policy-grid">
            <div class="policy-card">
              <label>
                <input type="checkbox" class="policy-toggle" data-policy-key="DeveloperToolsDisabled">
                <span><strong>Disable Developer Tools</strong>Sets <code>DeveloperToolsDisabled: true</code></span>
              </label>
            </div>
            <div class="policy-card">
              <label>
                <input type="checkbox" class="policy-toggle" data-policy-key="IncognitoModeAvailability" data-policy-value-on="1" data-policy-value-off="0">
                <span><strong>Disable Incognito</strong>Uses <code>IncognitoModeAvailability</code></span>
              </label>
            </div>
            <div class="policy-card">
              <label>
                <input type="checkbox" class="policy-toggle" data-policy-key="BrowserSignin" data-policy-value-on="0" data-policy-value-off="1">
                <span><strong>Disable Browser Sign-in</strong>Uses <code>BrowserSignin</code></span>
              </label>
            </div>
            <div class="policy-card">
              <label>
                <input type="checkbox" class="policy-toggle" data-policy-key="PasswordManagerEnabled">
                <span><strong>Enable Password Manager</strong>Sets <code>PasswordManagerEnabled: true</code></span>
              </label>
            </div>
            <div class="policy-card">
              <label>
                <input type="checkbox" class="policy-toggle" data-policy-key="PrintingEnabled">
                <span><strong>Enable Printing</strong>Sets <code>PrintingEnabled: true</code></span>
              </label>
            </div>
            <div class="policy-card">
              <label>
                <input type="checkbox" class="policy-toggle" data-policy-key="TranslateEnabled">
                <span><strong>Enable Translate</strong>Sets <code>TranslateEnabled: true</code></span>
              </label>
            </div>
          </div>
        </div>
        <label>
          <div class="note">Policy JSON</div>
          <textarea id="policyJson">{policy_text}</textarea>
        </label>
        <div class="row">
          <button type="submit">Push Update</button>
          <button type="button" class="secondary" id="load-sample">Load Sample Policy</button>
          <span id="flash"></span>
        </div>
        <div class="preview-grid">
          <div class="preview-card">
            <div class="note">Effective streamed policy JSON</div>
            <pre id="effectivePolicyPreview">{policy_text}</pre>
          </div>
          <div class="preview-card">
            <div class="note">Inner plaintext SSE payload</div>
            <pre id="innerPayloadPreview"></pre>
          </div>
          <div class="preview-card">
            <div class="note">Selected checkbox policies</div>
            <pre id="selectedPoliciesPreview"></pre>
          </div>
          <div class="preview-card">
            <div class="note">Last SSE event actually streamed</div>
            <pre id="lastStreamedPreview">No event streamed yet.</pre>
          </div>
        </div>
      </form>
    </section>
  </div>
  <script>
    const flash = document.getElementById('flash');
    const subscribersEl = document.getElementById('subscribers');
    const policyEl = document.getElementById('policyJson');
    const loginEl = document.getElementById('loginStatus');
    const toggles = Array.from(document.querySelectorAll('.policy-toggle'));
    const effectivePolicyPreviewEl = document.getElementById('effectivePolicyPreview');
    const innerPayloadPreviewEl = document.getElementById('innerPayloadPreview');
    const selectedPoliciesPreviewEl = document.getElementById('selectedPoliciesPreview');
    const lastStreamedPreviewEl = document.getElementById('lastStreamedPreview');
    let autoPushTimer = null;
    let pushInFlight = false;
    let lastSubmittedBody = '';

    function stableStringify(value) {{
      return JSON.stringify(value, null, 2);
    }}

    function computeSelectedPolicies(policy) {{
      const selected = {{}};
      toggles.forEach((toggle) => {{
        const key = toggle.dataset.policyKey;
        if (key in policy) {{
          selected[key] = policy[key];
        }}
      }});
      return selected;
    }}

    function refreshPreview(policy) {{
      const effectivePolicy = policy || parsePolicyJson();
      const selectedPolicies = computeSelectedPolicies(effectivePolicy);
      const innerPayload = {{
        policydata: btoa(unescape(encodeURIComponent(JSON.stringify(effectivePolicy)))),
        loginStatus: loginEl.checked
      }};

      effectivePolicyPreviewEl.textContent = stableStringify(effectivePolicy);
      innerPayloadPreviewEl.textContent = stableStringify(innerPayload);
      selectedPoliciesPreviewEl.textContent = stableStringify(selectedPolicies);
    }}

    function refreshLastStreamed(lastStreamedEvent) {{
      if (!lastStreamedEvent) {{
        lastStreamedPreviewEl.textContent = 'No event streamed yet.';
        return;
      }}

      lastStreamedPreviewEl.textContent = stableStringify(lastStreamedEvent);
    }}

    function buildSubmitBody() {{
      applyTogglesToJson();
      refreshPreview();
      return JSON.stringify({{
        loginStatus: loginEl.checked,
        policyJson: policyEl.value
      }});
    }}

    async function pushCurrentState(reason) {{
      if (pushInFlight) {{
        return;
      }}

      let body;
      try {{
        body = buildSubmitBody();
      }} catch (error) {{
        return;
      }}

      if (body === lastSubmittedBody && reason !== 'manual') {{
        return;
      }}

      pushInFlight = true;
      flash.textContent = reason === 'manual' ? 'Sending...' : 'Auto-updating...';
      try {{
        const res = await fetch('/api/update', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body
        }});
        const data = await res.json();
        if (!res.ok) {{
          throw new Error(data.error || 'Request failed');
        }}

        lastSubmittedBody = body;
        subscribersEl.textContent = data.subscribers;
        policyEl.value = JSON.stringify(JSON.parse(data.policyJson), null, 2);
        syncTogglesFromJson();
        refreshPreview(JSON.parse(data.policyJson));
        refreshLastStreamed(data.lastStreamedEvent);
        flash.textContent = reason === 'manual' ? 'Update pushed' : 'Auto-updated';
      }} catch (error) {{
        flash.textContent = error.message;
      }} finally {{
        pushInFlight = false;
      }}
    }}

    function scheduleAutoPush(reason) {{
      if (autoPushTimer) {{
        clearTimeout(autoPushTimer);
      }}
      autoPushTimer = setTimeout(() => {{
        pushCurrentState(reason);
      }}, 350);
    }}

    function parsePolicyJson() {{
      try {{
        return JSON.parse(policyEl.value || '{{}}');
      }} catch (error) {{
        flash.textContent = 'Policy JSON is invalid';
        throw error;
      }}
    }}

    function syncTogglesFromJson() {{
      let policy;
      try {{
        policy = JSON.parse(policyEl.value || '{{}}');
      }} catch (error) {{
        return;
      }}

      toggles.forEach((toggle) => {{
        const key = toggle.dataset.policyKey;
        const onValue = toggle.dataset.policyValueOn;
        const offValue = toggle.dataset.policyValueOff;
        const current = policy[key];

        if (onValue !== undefined && offValue !== undefined) {{
          toggle.checked = String(current) === onValue;
          return;
        }}

        toggle.checked = current === true;
      }});
    }}

    function applyTogglesToJson() {{
      const policy = parsePolicyJson();

      toggles.forEach((toggle) => {{
        const key = toggle.dataset.policyKey;
        const onValue = toggle.dataset.policyValueOn;
        const offValue = toggle.dataset.policyValueOff;

        if (onValue !== undefined && offValue !== undefined) {{
          policy[key] = toggle.checked ? JSON.parse(onValue) : JSON.parse(offValue);
          return;
        }}

        if (toggle.checked) {{
          policy[key] = true;
        }} else if (key in policy) {{
          delete policy[key];
        }}
      }});

      policyEl.value = JSON.stringify(policy, null, 2);
      refreshPreview(policy);
    }}

    document.getElementById('load-sample').addEventListener('click', () => {{
      policyEl.value = JSON.stringify({{
        HomepageLocation: "https://example.com",
        RestoreOnStartup: 4,
        RestoreOnStartupURLs: ["https://example.com", "https://chromium.org"],
        BrowserSignin: 0
      }}, null, 2);
      syncTogglesFromJson();
      refreshPreview();
      scheduleAutoPush('sample');
    }});

    toggles.forEach((toggle) => {{
      toggle.addEventListener('change', () => {{
        try {{
          applyTogglesToJson();
          flash.textContent = 'Policy JSON updated from toggles';
          scheduleAutoPush('toggle');
        }} catch (error) {{
        }}
      }});
    }});

    policyEl.addEventListener('input', () => {{
      syncTogglesFromJson();
      refreshPreview();
      scheduleAutoPush('editor');
    }});

    loginEl.addEventListener('change', () => {{
      refreshPreview();
      scheduleAutoPush('login');
    }});

    document.getElementById('control-form').addEventListener('submit', async (event) => {{
      event.preventDefault();
      await pushCurrentState('manual');
    }});

    async function refreshState() {{
      try {{
        const res = await fetch('/api/state');
        const data = await res.json();
        subscribersEl.textContent = data.subscribers;
        refreshLastStreamed(data.lastStreamedEvent);
      }} catch (error) {{
      }}
    }}

    setInterval(refreshState, 2000);
    syncTogglesFromJson();
    refreshPreview();
  </script>
</body>
</html>
"""


class PolicyTestHandler(BaseHTTPRequestHandler):
    server_version = "HyConnectPolicyTest/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.handle_index()
            return
        if parsed.path == "/api/state":
            self.handle_api_state()
            return
        if parsed.path in ("/streamPluginPolicy", "/ClientStatus"):
            self.handle_sse()
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/update":
            self.handle_api_update()
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def log_message(self, fmt: str, *args: object) -> None:
        print(
            "[%s] %s"
            % (time.strftime("%H:%M:%S"), fmt % args),
            flush=True,
        )

    def handle_index(self) -> None:
        html = build_html(SHARED_STATE.get_state(), SHARED_STATE.subscriber_count()).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def handle_api_state(self) -> None:
        state = SHARED_STATE.get_state()
        last_event = SHARED_STATE.last_streamed_event()
        self.send_json(
            {
                "loginStatus": state.login_status,
                "policyJson": state.policy_json_text,
                "subscribers": SHARED_STATE.subscriber_count(),
                "lastStreamedEvent": None
                if last_event is None
                else {
                    "eventId": last_event.event_id,
                    "source": last_event.source,
                    "loginStatus": last_event.login_status,
                    "effectivePolicyJson": last_event.effective_policy_json,
                    "innerPayloadJson": last_event.inner_payload_json,
                    "awcDataB64": last_event.awc_data_b64,
                    "plaintextBytes": last_event.plaintext_bytes,
                    "ciphertextBytes": last_event.ciphertext_bytes,
                },
            }
        )

    def handle_api_update(self) -> None:
        try:
            body = self.read_json_body()
            login_status = bool(body.get("loginStatus", False))
            policy_json_text = str(body.get("policyJson", "{}"))
            state = SHARED_STATE.set_state(login_status, policy_json_text)
            log(
                "Control page updated state: "
                f"loginStatus={state.login_status}, policy={state.normalized_policy_json()}"
            )
        except Exception as exc:
            log(f"Control page update rejected: {exc}")
            self.send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return

        SHARED_STATE.broadcast(source="control-page")
        last_event = SHARED_STATE.last_streamed_event()
        log(
            "Control page broadcast complete: "
            f"subscribers={SHARED_STATE.subscriber_count()}, "
            f"last_event_id={None if last_event is None else last_event.event_id}"
        )
        self.send_json(
            {
                "ok": True,
                "loginStatus": state.login_status,
                "policyJson": state.policy_json_text,
                "subscribers": SHARED_STATE.subscriber_count(),
                "lastStreamedEvent": None
                if last_event is None
                else {
                    "eventId": last_event.event_id,
                    "source": last_event.source,
                    "loginStatus": last_event.login_status,
                    "effectivePolicyJson": last_event.effective_policy_json,
                    "innerPayloadJson": last_event.inner_payload_json,
                    "awcDataB64": last_event.awc_data_b64,
                    "plaintextBytes": last_event.plaintext_bytes,
                    "ciphertextBytes": last_event.ciphertext_bytes,
                },
            }
        )

    def handle_sse(self) -> None:
        handshake_b64 = self.headers.get(NOISE_HANDSHAKE_HEADER)
        if not handshake_b64:
            log("Rejecting SSE request: missing X-Noise-Handshake header")
            self.send_json({"error": "missing Noise handshake header"}, status=HTTPStatus.BAD_REQUEST)
            return

        try:
            client_handshake = b64decode(handshake_b64.strip())
            log(f"Received client handshake bytes={len(client_handshake)}")
            session = NativeNoiseResponderSession(RESPONDER_PRIVATE_KEY)
            session.read_handshake_message(client_handshake)
            server_handshake = session.write_handshake_message()
            log(f"Noise handshake accepted, response bytes={len(server_handshake)}")
        except Exception as exc:
            log(f"Noise handshake failed: {exc}")
            self.send_json({"error": f"handshake failed: {exc}"}, status=HTTPStatus.BAD_REQUEST)
            return

        subscriber = Subscriber(self, session)
        SHARED_STATE.add_subscriber(subscriber)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header(NOISE_HANDSHAKE_HEADER, b64encode(server_handshake))
        self.end_headers()

        subscriber.send_state(SHARED_STATE.get_state(), source="bootstrap")

        try:
            while True:
                time.sleep(1.0)
        except Exception as exc:
            log(f"SSE loop ended: {exc}")
        finally:
            subscriber.close()

    def read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length)
        return json.loads(raw_body.decode("utf-8"))

    def send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class KeepAliveThread(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)

    def run(self) -> None:
        while True:
            time.sleep(KEEPALIVE_INTERVAL_SECONDS)
            SHARED_STATE.keepalive()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HyConnect Noise/SSE policy test server")
    parser.add_argument("--host", default=SERVER_HOST, help="Host to bind")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help="Port to bind")
    parser.add_argument("--no-open", action="store_true", help="Do not open the control page")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), PolicyTestHandler)
    KeepAliveThread().start()

    url = f"http://{args.host}:{args.port}/"
    log(f"HyConnect test server listening on {url}")
    log(f"Browser SSE endpoint: http://127.0.0.1:{args.port}/streamPluginPolicy")
    log(f"Pinned responder public key: {SERVER_STATIC_PUBLIC_KEY_HEX}")

    if not args.no_open:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
