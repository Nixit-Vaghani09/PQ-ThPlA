# PQ-ThPlA: Post-Quantum Threshold Passwordless Authentication

PQ-ThPlA is a high-assurance, quantum-resilient authentication and secure session framework written in Rust. It eliminates single points of failure and classical public-key vulnerabilities by synthesizing Post-Quantum Cryptography (PQC), Shamir's Secret Sharing, and Merkle tree batch commitments.

---

## 1. Architectural Overview

Traditional authentication protocols rely on classical asymmetric algorithms such as RSA, ECDSA, or Ed25519, which are fundamentally vulnerable to polynomial-time Shor's algorithm on cryptanalytically relevant quantum computers (CRQCs). Furthermore, centralized authentication authorities introduce single points of compromise.

PQ-ThPlA solves these challenges through a three-tier architecture:
- **Stateless Hash-Based Signatures (SLH-DSA / SPHINCS+)**: Provides quantum-safe identity proofing without relying on lattice hardness assumptions.
- **Merkle Tree Challenge Aggregation**: Combines multi-server authentication challenges into a single cryptographic root, enabling a client to authenticate across $n$ servers with a single post-quantum signature.
- **Formally Verified Post-Quantum KEM (ML-KEM-768)**: Leverages `libcrux-ml-kem` to establish forward-secure, quantum-resistant session channels hardened with AES-256-GCM.

```
                           +-----------------------------------+
                           |            User Token             |
                           +-----------------------------------+
                             |       ^                   ^
          1. AuthRequest     |       | 2. Challenges     | 3. AuthResponses
         (User, SessionID)   |       |    (ServerIDs,    |    (Merkle Proofs,
                             |       |     Nonces)       |     Single Signature)
                             v       |                   |
        +-------------------------------------------------------------+
        |                 Distributed Server Cluster                  |
        |                                                             |
        |  +------------------+  +------------------+  +-----------+  |
        |  |  Auth Server 1   |  |  Auth Server 2   |  | Server N  |  |
        |  |  (Shamir Share)  |  |  (Shamir Share)  |  | (...)     |  |
        |  +------------------+  +------------------+  +-----------+  |
        +-------------------------------------------------------------+
                                     |
                                     v
                       +---------------------------+
                       | Threshold Policy Decision |
                       |    (t-of-n Quorum Check)  |
                       +---------------------------+
```

---

## 2. Cryptographic Primitives & Specifications

| Primitive Type | Algorithm | Parameter Set / Variant | Standard / Specification | Key / Artifact Sizes |
| :--- | :--- | :--- | :--- | :--- |
| **Digital Signature (PQC)** | SLH-DSA / SPHINCS+ | SPHINCS+-SHAKE-128s-simple | NIST FIPS 205 Precursor (NIST Round 3) | Public Key: 32 bytes<br>Secret Key: 64 bytes<br>Signature: 7,856 bytes |
| **Key Encapsulation (PQC)** | ML-KEM | ML-KEM-768 (Kyber-768) | NIST FIPS 203 (Formally verified via F*) | Public Key: 1,184 bytes<br>Private Key: 2,400 bytes<br>Ciphertext: 1,088 bytes<br>Shared Secret: 32 bytes |
| **Symmetric AEAD** | AES-GCM | AES-256-GCM | NIST SP 800-38D | Key: 32 bytes<br>Nonce: 12 bytes (96 bits) |
| **Cryptographic Hash** | SHA-3 & SHA-2 | SHA3-256 / SHA-256 | FIPS 202 / FIPS 180-4 | Digest: 32 bytes (256 bits) |
| **Threshold Sharing** | Shamir's Secret Sharing | $t$-of-$n$ threshold over GF(256) | Applied Cryptography / Sharks | Variable byte slices |

---

## 3. Core Subsystems & Directory Layout

- `src/slh_dsa/`: Pure post-quantum digital signature subsystem. Manages key generation, detached signature generation, and verification using SPHINCS+-SHAKE-128s.
- `src/ml_kem/`: Formally verified ML-KEM-768 encapsulation, decapsulation, AES-256-GCM transport framing, nonce counters, anti-replay tracking, and cryptographic key rotation.
- `src/merkle_tree/`: SHA3-256 Merkle tree builder, leaf digest calculation, and inclusion proof generation and verification.
- `src/threshold/`: Shamir's Secret Sharing setup ($t$-of-$n$) and server share management with session nonce derivation.
- `src/challenge/`: Challenge structures containing server identifiers, session identifiers, and cryptographically secure random nonces.
- `src/registration/`: Full-threshold ($n$-of-$n$) registration protocol handler and proof validation.
- `src/auth/`: Interactive threshold ($t$-of-$n$) authentication protocol engine.
- `src/server/`: Server node state, credential store, authentication challenge generators, and threshold verification policies.
- `src/user/`: Client token workflows for batch challenge verification, Merkle root signing, and session handshake negotiation.

---

## 4. Protocol Workflows

### 4.1. User Registration (n-of-n Full Threshold)
1. **Initiation**: The client transmits a registration request containing a unique user identifier, session identifier, and initial registration nonce.
2. **Challenge Dispatch**: Every server node in the cluster verifies that the user does not exist in its credential store, generating a 32-byte OsRng nonce challenge.
3. **Merkle Aggregation**: The client hashes all server challenges using SHA3-256, constructs a balanced Merkle tree, and extracts the root digest.
4. **Root Signing**: The client generates a fresh SLH-DSA keypair and signs the Merkle root once.
5. **Multi-Proof Distribution**: The client computes individual Merkle inclusion proofs for each server and dispatches tailored registration response messages.
6. **Enrollment**: Each server verifies the Merkle proof for its specific challenge and validates the SLH-DSA signature against the Merkle root. Upon $n$-of-$n$ unanimous validation, the credential is stored.

### 4.2. User Authentication (t-of-n Quorum)
1. **Request**: The client broadcasts an authentication request containing user and session identifiers.
2. **Challenge Generation**: Registered servers look up the user's public credential and return unique 32-byte challenges.
3. **Single-Signature Multi-Server Response**: The client builds a Merkle tree from all received challenges, signs the root with its private SLH-DSA key, and generates individual Merkle proofs.
4. **Verification**: Each server independently verifies that its challenge exists in the Merkle root and that the client's signature over the root is authentic.
5. **Access Evaluation**: The system evaluates if the total number of successful server verifications satisfies the threshold policy ($t$-of-$n$).

### 4.3. Post-Quantum Secure Session Handshake
1. **KEM Exchange**: The client and server perform an ML-KEM-768 key encapsulation handshake using `libcrux-ml-kem`.
2. **Session Key Derivation**: A 256-bit symmetric key is derived from the ML-KEM shared secret.
3. **Authenticated AEAD Channel**: Packets are encrypted with AES-256-GCM using monotonically incremented 96-bit nonces with embedded OS entropy.
4. **Replay Defense & Rotation**: Nonces are checked against an active replay filter. Keys are securely zeroized and rotated periodically or upon reaching packet thresholds.

---

## 5. Building, Testing, and Demonstrations

### Prerequisites
- Rust 2024 edition (or latest stable Rust toolchain).
- Hardware support for AVX2 or ARM NEON (optional, for SIMD acceleration in `libcrux`).

### Compilation
```bash
cargo build --release
```

### Running Unit & Integration Tests
```bash
cargo test
```

### Running Demonstrations
- **Registration Workflow**:
  ```bash
  cargo run --example registration_demo
  ```
- **Threshold Authentication Workflow**:
  ```bash
  cargo run --example authentication_demo
  ```
- **Combined End-to-End Registration & Authentication**:
  ```bash
  cargo run --example combined_demo
  ```
- **ML-KEM Post-Quantum Secure Channel Handshake**:
  ```bash
  cargo run --example handshake_demo_ml_kem
  ```
- **ECDH Classical Handshake (Benchmark Baseline)**:
  ```bash
  cargo run --example handshake_demo_ecdh
  ```

---

## 6. Security & Performance Considerations

- **Signature Bandwidth Optimization**: A standard SPHINCS+-SHAKE-128s signature is 7,856 bytes. Direct multi-server authentication would require transmitting $n \times 7,856$ bytes over the uplink. PQ-ThPlA amortizes this overhead by signing only the 32-byte Merkle root, resulting in a constant signature uplink payload regardless of the number of authentication servers.
- **Constant-Time Cryptography**: Key encapsulation and decapsulation rely on formally verified, constant-time routines in `libcrux-ml-kem`, eliminating microarchitectural timing leakages.
- **Memory Sanitization**: Critical session states, keys, and decrypted buffers implement `Zeroize` and `Drop` handlers to scrub secrets from RAM upon deallocation.
- **Production Hardening Considerations**:
  - Replace in-memory credential stores with distributed, encrypted-at-rest persistence.
  - Implement length-prefixed domain separation for challenge hashing to eliminate boundary sliding risks.
  - Upgrade SPHINCS+ Round 3 bindings to finalized NIST FIPS 205 (SLH-DSA) parameterizations upon crate availability.

---

## 7. License

Licensed under the Apache License, Version 2.0. See the `LICENSE` file for details.
