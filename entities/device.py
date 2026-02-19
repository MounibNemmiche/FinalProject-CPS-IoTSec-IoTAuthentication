import struct
from entities.vault import SecureVault
from entities.crypto_utils import (
    generate_random_key,
    aes_ecb_encrypt,
    aes_ecb_decrypt,
    xor_bytes,
)
from config import M, P


class IoTDevice:
    """
    IoT Device (Client) implementing the Secure Vault authentication protocol.
    Executes Steps 1, 3, and 5 of the handshake.
    """

    def __init__(self, device_id: str, vault: SecureVault):
        self.device_id = device_id
        self.vault = vault
        self.session_id = None
        # Transient state for current authentication session
        self._c2 = None
        self._r2 = None
        self._t1 = None

    def step1_initiate(self) -> dict:
        """
        Step 1: Client -> Server
        Send M1 = {device_id, session_id}
        """
        self.session_id = generate_random_key(8).hex()
        return {"device_id": self.device_id, "session_id": self.session_id}

    def step3_respond(self, m2: dict) -> dict:
        """
        Step 3: Client -> Server
        Receives M2 = {C1, r1} from server.
        Computes k1, generates C2, r2, t1, encrypts payload.
        Returns M3 = {ciphertext}
        """
        c1 = m2["C1"]
        r1 = m2["r1"]

        # Derive key k1 from challenge C1
        k1 = self.vault.derive_key_from_indices(c1)

        # Generate counter-challenge, nonce, and partial session key
        self._c2 = self.vault.generate_challenge(P)
        self._r2 = generate_random_key(M)
        self._t1 = generate_random_key(M)

        # Encode C2: 1 byte for length + P bytes for indices
        c2_encoded = struct.pack(f"B{len(self._c2)}B", len(self._c2), *self._c2)

        # Payload: r1 || t1 || c2_encoded || r2
        payload = r1 + self._t1 + c2_encoded + self._r2

        ciphertext = aes_ecb_encrypt(k1, payload)
        return {"ciphertext": ciphertext}

    def step5_finalize(self, m4: dict) -> bytes:
        """
        Step 5: Client finalizes authentication.
        Receives M4 = {ciphertext} from server.
        Decrypts, validates r2, computes session key, updates vault.
        Returns session_key.
        Raises ValueError if authentication fails.
        """
        # Derive key k2 from own challenge C2
        k2 = self.vault.derive_key_from_indices(self._c2)

        # Decrypt M4
        plaintext = aes_ecb_decrypt(k2, m4["ciphertext"])

        # Extract r2 and t2
        r2_received = plaintext[:M]
        t2 = plaintext[M : 2 * M]

        # Validate r2
        if r2_received != self._r2:
            raise ValueError("Authentication failed: r2 mismatch (server not authenticated)")

        # Compute session key
        session_key = xor_bytes(self._t1, t2)

        # Update vault
        self.vault.update(session_key)

        # Clear transient state
        self._c2 = None
        self._r2 = None
        self._t1 = None

        return session_key
