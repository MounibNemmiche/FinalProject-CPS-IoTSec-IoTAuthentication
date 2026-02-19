# IoT Secure Vault Authentication

**Cyber-Physical Systems and IoT Security** -- Final Project
MSc in ICT for Internet and Multimedia -- University of Padova

## Overview

This project is a Python-based simulation of the mutual authentication protocol described in the paper **"Authentication of IoT Device and IoT Server Using Secure Vaults"** by S. Srinivas, A. Kumar, et al.

The protocol uses a **Secure Vault** -- a shared set of symmetric keys between an IoT device and a server -- to perform lightweight mutual authentication via a challenge-response handshake. After each successful session, both sides update the vault using an HMAC-based mechanism, preventing replay and dictionary attacks.

Since this is a PC simulation (not running on constrained hardware like Arduino), **execution time (ms)** is used as a proxy for **energy consumption** to evaluate and compare the performance of three authentication methods:

| Method | Description |
|--------|-------------|
| **Secure Vault (SV)** | The paper's protocol -- XOR-based key derivation from vault indices, AES-128 encryption, HMAC vault updates |
| **ECC (P-256 ECDSA)** | Elliptic Curve Digital Signature Algorithm -- mutual auth via signing/verifying nonces |
| **Simple Password** | Hash-based challenge-response using SHA-256 with a pre-shared password |

### Authentication Protocol Flow

The Secure Vault protocol follows a 4-message mutual authentication handshake:

![Secure Vault handshake](Figures/01-The%20Secure%20Vault%20protocol%20follows%20a%204-message%20mutual%20authentication%20handshake.png)
---

## Repository Structure

```
FinalProject-CPS-IoTSec-IoTAuthentication/
|
|-- main.py                     # Entry point: protocol demo and experiment runner
|-- config.py                   # Global constants (N, M, P, experiment parameters)
|-- requirements.txt            # Python dependencies
|-- README.md                   # This file
|
|-- entities/                   # Core protocol implementation
|   |-- __init__.py
|   |-- crypto_utils.py         # Cryptographic primitives (AES, XOR, HMAC, padding)
|   |-- vault.py                # SecureVault class (key storage, derivation, update)
|   |-- device.py               # IoTDevice class (client-side: Steps 1, 3, 5)
|   |-- server.py               # IoTServer class (server-side: Steps 2, 4)
|
|-- experiments/                # Performance comparison experiments
|   |-- __init__.py
|   |-- experiments_comparison.py   # SV vs ECC vs Simple Password benchmarks
|   |-- results/                    # Generated output files
|       |-- bar_chart_comparison.png
|       |-- line_chart_scaling.png
|       |-- bar_chart_log_scale.png
|       |-- simulation_output_YYYYMMDD_HHMMSS.log
|
|-- .gitignore
```

### Key Files

| File | Description |
|------|-------------|
| `config.py` | Vault parameters (`N=16` keys, `M=16` bytes/key, `P=6` keys/challenge), experiment settings (device counts, number of runs), ECC curve selection |
| `entities/crypto_utils.py` | Low-level crypto: `aes_ecb_encrypt/decrypt` (AES-128-ECB with PKCS7 padding), `xor_bytes`, `xor_multiple_keys`, `compute_hmac` (HMAC-SHA256), `hmac_expand` (iterative HMAC expansion for vault update) |
| `entities/vault.py` | `SecureVault` class -- `initialize()` generates N random keys, `derive_key_from_indices()` XORs selected keys, `update()` performs HMAC-based vault refresh after each session |
| `entities/device.py` | `IoTDevice` class -- implements the client side of the handshake (`step1_initiate`, `step3_respond`, `step5_finalize`) |
| `entities/server.py` | `IoTServer` class -- implements the server side (`step2_challenge`, `step4_verify_and_respond`), manages registered devices and session state |
| `experiments/experiments_comparison.py` | Runs all three authentication methods, measures per-device timing with `time.perf_counter()`, generates PrettyTable console output and matplotlib plots |

---

## Requirements

- **Python** 3.10 or higher
- **Operating System**: Windows, macOS, or Linux

### Python Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `pycryptodome` | >= 3.20.0 | AES-ECB encryption/decryption, ECC key generation, ECDSA signing/verification, SHA-256 hashing |
| `prettytable` | >= 3.9.0 | Formatted console tables for experiment results |
| `matplotlib` | >= 3.8.0 | Bar charts, line charts, and log-scale plots for performance comparison |

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/FinalProject-CPS-IoTSec-IoTAuthentication.git
cd FinalProject-CPS-IoTSec-IoTAuthentication

# Install dependencies
pip install -r requirements.txt
```

---

## How to Run

### Run Everything (Demo + Experiments)

```bash
python main.py
```

This runs the protocol demo first, then the full experiment suite.

### Run Protocol Demo Only

```bash
python main.py --demo
```

Executes 3 consecutive authentication sessions between a single device and server, printing each step of the handshake with intermediate values (challenge indices, nonces, ciphertexts, session keys). Verifies that:
- Both sides derive the same session key
- Vaults remain synchronized across multiple sessions
- Mutual authentication succeeds (r1 and r2 validated)

### Run Experiments Only

```bash
python main.py --experiment
```

Benchmarks all three authentication methods (SV, ECC, Simple Password) across 5 device counts (10, 50, 100, 500, 1000 devices), averaged over 5 runs each. Outputs:
- Console tables with mean, standard deviation, min, and max timings
- Three plots saved to `experiments/results/`

---

## Simulation Output

### Demo Output

The demo prints a step-by-step trace of the authentication handshake:

```
============================================================
  IoT Secure Vault Authentication - Protocol Demo
============================================================

Parameters: N=16 keys, M=16 bytes/key, P=6 keys/challenge

[Setup] Initializing shared vault...
  Vault: 16 keys of 16 bytes each
  Device ID: Device_001

--------------------------------------------------
  Session 1/3
--------------------------------------------------

  [Step 1] Device -> Server: M1
    Device ID:  Device_001
    Session ID: 6b1621365e157a3d

  [Step 2] Server -> Device: M2
    Challenge C1: [1, 13, 3, 15, 8, 5]
    Nonce r1:     e92819c13189ef2a2885c349ac57961c...

  [Step 3] Device -> Server: M3
    Ciphertext:   964c55198f07e6037a29f2dbb454242f...
    (encrypted with k1 derived from C1)

  [Step 4] Server -> Device: M4
    Ciphertext:   babb89d2190b2913c22a8c1e75166b6b...
    Server verified r1 - device is authenticated!

  [Step 5] Finalization
    Device verified r2 - server is authenticated!
    Session Key (device): 37adb3871d3881d32d22ae773f1591d4...
    Session Key (server): 37adb3871d3881d32d22ae773f1591d4...
    Keys match: True
    Vault updated for next session.
```

### Experiment Console Output

The experiment suite produces two tables:

**Summary Table** -- average authentication time per device (ms) with standard deviation:

```
+-----------+-------------------+-------------------+-------------------+
| # Devices |    Secure Vault   |    ECC (P-256)    |  Simple Password  |
+-----------+-------------------+-------------------+-------------------+
|     10    | 0.1867 +/- 0.0656 | 2.0768 +/- 0.0371 | 0.0085 +/- 0.0003 |
|     50    | 0.1585 +/- 0.0031 | 2.0776 +/- 0.0369 | 0.0084 +/- 0.0004 |
|    100    | 0.1574 +/- 0.0036 | 2.0589 +/- 0.0139 | 0.0081 +/- 0.0000 |
|    500    | 0.1580 +/- 0.0013 | 2.0862 +/- 0.0686 | 0.0081 +/- 0.0001 |
|    1000   | 0.1586 +/- 0.0011 | 2.0550 +/- 0.0041 | 0.0081 +/- 0.0000 |
+-----------+-------------------+-------------------+-------------------+
```

**Detailed Breakdown Table** -- per method with min/max:

```
+-----------+-----------------+-----------+---------+----------+----------+
| # Devices |      Method     | Mean (ms) | Std Dev | Min (ms) | Max (ms) |
+-----------+-----------------+-----------+---------+----------+----------+
|     10    |   Secure Vault  |   0.1867  |  0.0656 |  0.1527  |  0.3034  |
|     10    |   ECC (P-256)   |   2.0768  |  0.0371 |  2.0500  |  2.1396  |
|     10    | Simple Password |   0.0085  |  0.0003 |  0.0083  |  0.0091  |
|    ...    |       ...       |    ...    |   ...   |   ...    |   ...    |
+-----------+-----------------+-----------+---------+----------+----------+
```

### Generated Plots

All plots are saved to `experiments/results/`:

| File | Description |
|------|-------------|
| `bar_chart_comparison.png` | Grouped bar chart comparing SV, ECC, and Simple Password at each device count (similar to Figure 3 in the reference paper) |
| `line_chart_scaling.png` | Line chart showing how authentication time scales with number of devices |
| `bar_chart_log_scale.png` | Same bar chart with logarithmic Y-axis, useful since ECC is ~13x slower than SV |

### Log File

Every run automatically saves a complete copy of all terminal output to a timestamped `.log` file in `experiments/results/`:

```
experiments/results/simulation_output_20260219_143025.log
```

The log file contains the exact same content shown in the terminal (demo trace, experiment progress, summary tables, plot save paths). This allows you to review past runs without re-executing the simulation.

---

## Configuration

All parameters are defined in `config.py` and can be adjusted:

```python
# Vault parameters
N = 16          # Number of keys in the vault (paper uses 128)
M = 16          # Key size in bytes (16 = AES-128)
P = 6           # Number of keys selected per challenge

# Experiment parameters
NUM_DEVICES_LIST = [10, 50, 100, 500, 1000]
NUM_RUNS = 5    # Runs to average per data point

# ECC parameters
ECC_CURVE = "P-256"

# Simple password parameters
PASSWORD_LENGTH = 16  # bytes
```

### Why N=16, M=16, P=6?

| Parameter | Value | Justification |
| --------- | ----- | ------------- |
| **N** (vault size) | 16 | The reference paper uses N=128, but since this is a PC-based simulation (not constrained hardware), N=16 is sufficient to demonstrate the protocol correctly while keeping execution time reasonable. With N=16 and P=6, the number of possible challenges is C(16, 6) = **8,008**, which still provides adequate entropy for the challenge space. |
| **M** (key size) | 16 bytes | 16 bytes = 128 bits, matching the **AES-128** standard key length. This is the widely accepted minimum for secure symmetric encryption and is consistent with the paper's use of AES-based operations. |
| **P** (keys per challenge) | 6 | Balances security against computational cost. Selecting 6 out of 16 keys per challenge yields 8,008 distinct challenges -- enough to prevent brute-force enumeration while keeping the XOR-based key derivation lightweight. |

### Parameter Constraints

Each parameter has hard requirements imposed by the implementation:

| Parameter | Valid Range | Constraint Reason |
| --------- | ----------- | ----------------- |
| **N** | 2 -- 255 | Must be > P (otherwise `random.sample(range(N), P)` fails). Upper bound of 255 because challenge indices are encoded as single bytes via `struct.pack("B", ...)` in the M3 message. |
| **M** | 16 or 32 | Must be a valid AES key size. `AES.new(key, AES.MODE_ECB)` only accepts 16 bytes (AES-128) or 32 bytes (AES-256). M is used for vault keys, nonces (r1, r2), partial session keys (t1, t2), and derived keys (k1, k2). |
| **P** | 2 -- N-1 | Must be >= 2 (XORing fewer than 2 keys provides no meaningful derivation). Must be < N (cannot select more indices than exist in the vault). |

### Impact of Changing Parameters

| Change | Security | Memory | Performance |
| ------ | -------- | ------ | ----------- |
| **Increase N** (e.g. 16 -> 128) | Larger challenge space C(N, P) -- harder to brute-force which keys were selected | More memory per vault: N x M bytes stored on both device and server | Slower vault update -- HMAC expansion must generate N x M bytes after each session |
| **Increase M** (16 -> 32) | Switches from AES-128 to AES-256 -- stronger encryption with a larger security margin | Doubles vault memory (N x 32 instead of N x 16). Nonces and session keys also double in size | Slightly slower AES operations and larger encrypted payloads in M3/M4 messages |
| **Increase P** (e.g. 6 -> 12) | Larger challenge space C(N, P) and more keys XORed together -- harder to recover individual vault keys | No significant memory impact | More XOR operations per key derivation. Larger M3 payload (C2 indices are sent encrypted) |
| **Decrease P** (e.g. 6 -> 2) | Much smaller challenge space C(N, 2) -- easier to enumerate. Derived key depends on fewer vault keys | No significant memory impact | Faster key derivation (fewer XOR operations) |

---

## References

1. **S. Srinivas, A. Kumar, et al.** -- *"Authentication of IoT Device and IoT Server Using Secure Vaults"*, IEEE Internet of Things Journal. The reference paper that this project implements and evaluates. [(PDF included in repository)](Authentication_of_IoT_Device_and_IoT_Server_Using_Secure_Vaults.pdf)

2. **PyCryptodome** -- Python cryptographic library used for AES-128-ECB encryption/decryption, ECC P-256 key generation, ECDSA digital signatures, and SHA-256 hashing. https://www.pycryptodome.org/

3. **Python `hmac` module** -- Standard library module used for HMAC-SHA256 computation in vault update operations. https://docs.python.org/3/library/hmac.html

4. **Python `hashlib` module** -- Standard library module providing SHA-256 hash function. https://docs.python.org/3/library/hashlib.html

5. **PrettyTable** -- Python library for formatted ASCII table output. https://github.com/jazzband/prettytable

---

