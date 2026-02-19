import copy
import random
from config import N, M, P
from entities.crypto_utils import (
    generate_random_key,
    xor_multiple_keys,
    xor_bytes,
    hmac_expand,
)


class SecureVault:
    """
    Secure Vault: stores N symmetric keys of M bytes each.
    Supports challenge-based key derivation and HMAC-based vault updates.
    """

    def __init__(self, n: int = N, m: int = M):
        self.n = n
        self.m = m
        self.keys: list[bytes] = []

    def initialize(self) -> None:
        """Generate N random keys of M bytes each."""
        self.keys = [generate_random_key(self.m) for _ in range(self.n)]

    def clone(self) -> "SecureVault":
        """Deep copy of this vault (used to share initial state between device and server)."""
        return copy.deepcopy(self)

    def get_key(self, index: int) -> bytes:
        """Return the key at the given index."""
        return self.keys[index]

    def derive_key_from_indices(self, indices: list[int]) -> bytes:
        """XOR all keys at the given indices to produce a derived key (k1 or k2)."""
        selected_keys = [self.keys[i] for i in indices]
        return xor_multiple_keys(selected_keys)

    def generate_challenge(self, p: int = P) -> list[int]:
        """Generate a random challenge: p unique indices from [0, N-1]."""
        return random.sample(range(self.n), p)

    def update(self, session_key: bytes) -> None:
        """
        Update all vault keys after a successful authentication session.
        Uses HMAC-based expansion to generate N*M bytes, then XORs
        each key with its corresponding partition.

        This must be called identically on both device and server
        to keep vaults synchronized.
        """
        vault_concat = b"".join(self.keys)
        expanded = hmac_expand(session_key, vault_concat, self.n * self.m)

        for i in range(self.n):
            partition = expanded[i * self.m : (i + 1) * self.m]
            self.keys[i] = xor_bytes(self.keys[i], partition)
