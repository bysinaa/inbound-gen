# Inbound Gen

Local Windows web app for discovering a 3x-ui server over SSH, creating an inbound through the panel API, and testing the real relay from the Windows network.

## Start

Right-click `start.ps1` and choose **Run with PowerShell**, or run:

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

The app opens `http://127.0.0.1:8765`. It never listens on the LAN.

## Security

- The SSH password and 3x-ui API token live only in process memory and disappear when the app closes.
- The first connection requires explicit confirmation of the SSH SHA-256 host fingerprint.
- If a newly created inbound fails its three real relay tests, it is disabled rather than deleted.
- Port `0` auto-selects a free well-known port. The app opens it in active UFW/firewalld before testing and removes only the rule it added when the relay test fails.
- Share links and private keys are never returned to the browser or written to disk.
- New inbounds reuse one panel client named `inbound-gen`; the panel attaches that client to each working configuration instead of creating timestamped users.

## Supported templates

- VLESS HTTPUpgrade without TLS
- VLESS WebSocket TLS
- VLESS XHTTP TLS
- VLESS TCP REALITY
- VMess WebSocket TLS
- Trojan WebSocket TLS
- Trojan TCP TLS

The bundled local Xray is used in an isolated temporary directory; normal v2rayN profiles are not touched.

## Smart build

Paste only your domains and optional clean CDN addresses. The app classifies direct versus CDN DNS, obtains a missing origin certificate through 3x-ui's SSL management, tries a bounded Reality/WS/XHTTP/HTTPUpgrade matrix, and stops at the first configuration that passes the real local relay test. Smart-build trials that fail are removed before the next variation, so only the first working result remains; the app never loops forever.
