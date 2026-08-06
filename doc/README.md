# Documentation

Technical documentation for SecureBit.chat. Start with the project [README](../README.md)
if you are looking for an overview or a quick start.

| Document | What it covers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How a session is established, verified and torn down, and where each guarantee comes from |
| [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) | Key schedule, the Double Ratchet, SAS verification, memory handling |
| [CONFIGURATION.md](CONFIGURATION.md) | Deployment, ICE and TURN setup, privacy modes, file transfer policy |
| [CALLS.md](CALLS.md) | Voice and video: codec choices, adaptation, and why each value was picked |
| [API.md](API.md) | Internal interfaces of the WebRTC manager and file transfer system |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development workflow and what needs extra review |
| [USE-POLICY.md](USE-POLICY.md) | Terms of use, intended use, and the limits of what the software can protect |

Security policy and vulnerability reporting live in [SECURITY.md](../SECURITY.md) at
the repository root, where GitHub expects to find them.

## Keeping this accurate

These documents describe the current release and are expected to change with it.
Every value quoted here (limits, timeouts, algorithm parameters) is taken from the
source rather than restated from memory, so if you change one in code, change it
here in the same commit. [CONTRIBUTING.md](CONTRIBUTING.md) lists which documents
are affected by which areas of the code.
