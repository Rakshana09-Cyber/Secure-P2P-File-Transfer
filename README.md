# Secure Peer-to-Peer File Transfer

A browser-based student project prototype for transferring files between two browsers.

## Security and networking components
- PeerJS / WebRTC DataChannel: peer discovery/signaling and browser-to-browser data transport.
- ECDH P-256: shared-secret agreement.
- HKDF-SHA-256: derives an AES key from the shared secret.
- AES-256-GCM: authenticated encryption of file chunks.
- SHA-256: verifies the received file against the sender's hash.

## Project structure
```text
Secure-P2P-File-Transfer/
├── static/
│   ├── app.js
│   └── style.css
├── templates/
│   └── index.html
├── app.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Run locally on Windows
1. Install Python 3.10 or newer.
2. Open this folder in VS Code and open Terminal.
3. Create a virtual environment:
   ```powershell
   py -m venv .venv
   ```
4. Activate it:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and activate again.
5. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
6. Start Flask:
   ```powershell
   python app.py
   ```
7. Open `http://127.0.0.1:5000` in two browser sessions. Each session gets its own Peer ID. The sender pastes the receiver's ID.

Keep both browser tabs open during the transfer. Both browsers need internet access to reach the PeerJS signaling service.

## Deploy on Render
Create a **Web Service** from this GitHub repository and use:
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`
- Instance type: Free (if available in your account)

Render provides an HTTPS `onrender.com` URL. Open the same URL in both peers' browsers.

## Important prototype limitations
- The browser currently reads the selected file into memory before sending. Very large files may use substantial memory.
- Transfer requires both peers to remain online with the page open.
- WebRTC connectivity may depend on network/firewall/NAT conditions; a TURN relay may be needed on some networks.
- A Peer ID is an address, not an authenticated identity. Do not use this prototype for confidential production transfers without adding peer authentication, key confirmation, abuse controls, and security review.
- The signaling service helps peers discover each other; it is not the file-storage server.
