# Technical Deep Dive

## SNI Extraction

Even though HTTPS traffic is encrypted, the very first packet sent by the client (the TLS Client Hello) is transmitted in **plaintext**. 

This engine intercepts this packet, traverses the TLS record header, skips the session IDs and cipher suites, and scans the extensions payload for the `0x0000` (Server Name Indication) extension to extract the target domain (e.g., `www.youtube.com`). This allows the engine to accurately identify and block HTTPS applications without breaking end-to-end encryption.
