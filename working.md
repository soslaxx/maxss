# MAXSS: How It Works

## Protocol Workflow

- Transport: `TLS 1.3 + WebSocket (wss)` over TCP.
- Camouflage: configurable `SNI` and HTTPS-like traffic profile.
- Tunnel setup: the client opens WebSocket on a service path and completes the handshake.
- Authentication: username/password (or `hash:` mode) plus access check for a specific config `NAME`.
- Session keying: ephemeral `X25519` + `HKDF-SHA512` for per-session key derivation.
- Frame protection: layered crypto stack (TLS + inner AEAD/integrity/masking) to protect confidentiality and tamper resistance.
- Obfuscation: padding, jitter, and variable frame sizes.
- Data relay: after handshake, a CONNECT-like stage starts and TCP traffic is relayed inside encrypted frames.

## What Was Reused and From Where

- VLESS/XTLS architecture ideas, stealth transport approach, and config model:
  - https://github.com/XTLS/Xray-core
- Handshake/key-schedule patterns and X25519+HKDF practices:
  - https://github.com/XTLS/REALITY
- Deployment and transport camouflage examples:
  - https://github.com/XTLS/Xray-examples
- Runtime management and external control patterns:
  - https://github.com/XTLS/libXray
- Performance and obfuscation ideas for transport-level traffic:
  - https://github.com/apernet/hysteria
- Low-cost disguise/noise insertion concepts:
  - https://github.com/amnezia-vpn/amneziawg-go
