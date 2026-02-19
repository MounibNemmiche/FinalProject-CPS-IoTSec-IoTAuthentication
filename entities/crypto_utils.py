import os
import hmac
import hashlib
from functools import reduce
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def generate_random_key(size: int = 16) -> bytes:
    """Generate a cryptographically secure random key."""
    return os.urandom(size)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def xor_multiple_keys(keys: list) -> bytes:
    """XOR a list of keys together (used for challenge-response key derivation)."""
    return reduce(xor_bytes, keys)


def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-ECB encrypt with PKCS7 padding."""
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded)


def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES-ECB decrypt and remove PKCS7 padding."""
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, AES.block_size)


def compute_hmac(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_expand(key: bytes, data: bytes, length: int) -> bytes:
    """
    Expand HMAC output to produce `length` bytes.
    Uses iterative HMAC (similar to HKDF-Expand) to generate
    enough bytes for vault update when HMAC-SHA256 output (32 bytes)
    is shorter than needed.
    """
    result = b""
    counter = 1
    previous = b""
    while len(result) < length:
        previous = compute_hmac(key, previous + data + counter.to_bytes(1, "big"))
        result += previous
        counter += 1
    return result[:length]
