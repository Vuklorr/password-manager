# Security status

Guard is an educational password-manager prototype. It has not received an independent security audit and is not recommended as the primary store for real credentials.

Implemented controls include client-side AES-256-GCM encryption, separate HKDF-derived authentication/encryption keys, strict HTTPS-origin matching for autofill, session expiration, and account isolation. Passing tests do not establish the security of the whole system.

## Known limits

- A compromised application server can serve modified JavaScript that steals secrets on the next login.
- A compromised browser, extension, operating system, or legitimate destination site can read credentials while they are in use.
- The extension holds the decryption key in trusted `chrome.storage.session` memory during a session.
- There is no TOTP/WebAuthn second factor, password/key rotation, or account recovery.
- Automatic backup import and a complete restore procedure are not implemented or validated.
- HTTPS, proxy request limits, and shared production rate limiting must be configured for a network deployment.
- The extension and web application have separate sessions; signing out of one does not sign out of the other.

Use synthetic credentials while developing. Never commit `.env`, emergency kits, private keys, personal vault exports, or database dumps. `.gitignore` does not remove files already committed to Git history.

## Reporting a vulnerability

Do not post real credentials, recovery secrets, database dumps, or exploit details that expose user data in a public issue. If the GitHub repository enables private vulnerability reporting, use its Security tab. Otherwise contact the repository maintainer privately; no dedicated security contact or response-time commitment has been configured yet.
