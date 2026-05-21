# Security Policy

R2N is committed to maintaining a secure and reliable virtual networking overlay. Because virtual LAN software operates directly on host network interfaces, manages system routing tables, and encapsulates system-wide traffic, security is a core priority. This document outlines the security architecture, threat model, cryptographic primitives, and vulnerability disclosure processes for R2N.

---

## Security Architecture & Threat Model

R2N is built around a zero-trust architecture regarding the coordination and signaling infrastructure. The security model ensures that data confidentiality, integrity, and room isolation are preserved even if the coordination supernode is fully compromised.

### 1. End-to-End Cryptographic Dataplane (E2EE)
All traffic traversing the virtual LAN is encrypted end-to-end between edge peers (`r2n-edge` instances).
- **Session Handshake**: Secure tunnel establishment uses the **Noise Protocol Framework** (specifically utilizing the `Noise_XX_25519_ChaChaPoly_SHA256` pattern) for mutual authentication and session key derivation. This ensures Perfect Forward Secrecy (PFS) for all virtual LAN connections.
- **Payload Protection**: Dataplane packets are encrypted and authenticated using **ChaCha20-Poly1305 AEAD**. Replay attacks are prevented via strictly incremented 64-bit packet sequence counters.
- **Rekeying**: Session keys are dynamically rotated to limit the volume of ciphertext generated under a single key.

### 2. Zero-Trust Supernode Boundary
The supernode (`r2n-supernode`) manages control-plane coordination (rendezvous, NAT candidate exchange, and room memberships) and provides fallback relaying when direct P2P connection paths are blocked.
- **Relay Isolation**: The supernode acts purely as a transport relay. It does *not* participate in the Noise handshake between edge peers and does *not* possess the cryptographic room keys or derived session keys.
- **Threat Mitigation**: A compromised or malicious supernode can only inspect network metadata (source/destination public IPs, packet timing, room membership events, and relay bandwidth usage). It cannot decrypt or modify the payloads of the virtual LAN traffic.

### 3. Cryptographically Signed Invite Tokens
To join a virtual LAN room, a peer must present a cryptographically signed invite token. 
- **Token Structure**: The token is represented by `InviteData` (defined in `crates/r2n-common/src/lib.rs`), which contains the primary and fallback supernode addresses, the 16-byte `RoomId`, the 32-byte room public key (`room_pub_key`), the virtual CIDR subnet, an optional authentication token, and an expiration timestamp.
- **Signature & Serialization**: The token is serialized using the compact `postcard` format and signed using the **Ed25519** signature algorithm (using the `ed25519_dalek` crate). The entire signed payload is base64-encoded (without padding) into an invite code.
- **Access Control**: Room membership cannot be brute-forced or guessed. Unauthorized peers cannot inject themselves into a room or connect to existing room members without a signature verified against the room's authority public key.

### 4. Privilege Separation & IPC Security Boundary
Creating virtual interfaces and modifying OS routing tables require elevated privileges. R2N segregates these high-risk operations:
- **Daemon (`r2n-edge`)**: Runs as a privileged process (e.g., `root` on Linux/macOS or `SYSTEM` on Windows) to manage the TUN/TAP devices and update the host's routing tables.
- **Client (`r2n-cli`)**: Runs with unprivileged user access, communicating with the daemon over local IPC.
- **IPC Access Controls**:
  - On Unix platforms, the IPC path defaults to `/tmp/r2n_ipc_<user>.sock`. The socket file permissions are strictly restricted to the owning user (`0700`), ensuring that other local users cannot control the daemon.
  - On Windows, the IPC path utilizes Named Pipes (`\\.\pipe\r2n_ipc`), configured with strict Security Descriptors (ACLs) to restrict access to authorized local callers.
  - The IPC handler enforces strict schema validation using JSON-RPC-style parsing to prevent input injection attacks.

---

## Supported Versions

R2N is currently in an active pre-release development stage. Security support is focused on the latest commit on the main branch:

| Version | Supported |
| ------- | --------- |
| `main`  | Yes       |
| Commit tags / Snapshots | Best effort (please upgrade to main) |

Security patches will be landed on the default branch. We do not currently backport security fixes to older tags.

---

## Scope of Interest

We welcome reports regarding any behavior that breaks our security guarantees, including:
- **Cryptography**: Misuse of the Noise Protocol, key generation flaws, key leakage, or weak PRNGs.
- **Access Control**: Invites forgery, bypassing room boundaries, or joining rooms without valid signed invites.
- **Memory Safety**: Buffer overflows, memory corruption, or double-free conditions within the UDP deserialization, packet classification (`r2n-discovery`), or policy routing (`r2n-policy`) code.
- **Isolation**: Leaking virtual LAN packets to the public interface, or failing to isolate traffic between different active virtual rooms on the same host.
- **Denial of Service (DoS)**: High-performance packet reflection vectors or CPU exhaustion loops in the dataplane parsing logic.

---

## Reporting a Vulnerability

> [!IMPORTANT]
> Please do **not** report security vulnerabilities through public GitHub issues, discussions, or pull requests.

To report a vulnerability:
Please submit a report privately via **GitHub Private Vulnerability Reporting** (PVR) under the repository's "Security" tab. We only accept vulnerability reports through this GitHub channel.

Please include:
- A description of the vulnerability and its potential impact.
- The affected component/crate (e.g., `r2n-dataplane`, `r2n-crypto`).
- Step-by-step reproduction instructions, including configuration options.
- A proof-of-concept (PoC) script or packet capture, if available.

---

## Disclosure and Safe Harbor

- **Coordinated Disclosure**: We ask that you give us a reasonable period to investigate, fix, and release a patch before disclosing the vulnerability publicly.
- **Safe Harbor**: If you conduct vulnerability research in good faith, avoid violating user privacy, do not destroy data, and do not disrupt services, we will treat your research as authorized. We will not pursue legal action against you.
