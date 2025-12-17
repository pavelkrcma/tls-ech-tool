# TLS 1.3 ECH Tool

A command-line tool written in Go that establishes TLS 1.3 connections with Encrypted Client Hello (ECH) support.

## Purpose

This tool demonstrates and tests TLS 1.3 connections with ECH, automatically fetching ECH configuration from DNS HTTPS records. It provides detailed connection information including TLS version, cipher suite, certificate details, and ECH acceptance status.

## Requirements

- Go 1.24 or newer (for ECH support in crypto/tls)

## Installation

```bash
go build -o tls-ech-tool
```

## Usage

Run `./tls-ech-tool -h` to see all available options.

`./tls-ech-tool -v crypto.cloudflare.com`

`./tls-ech-tool -v -sni supersecret www.cnn.com`

## ESNI and ECH

### Background

Server Name Indication (SNI) is a TLS protocol feature that allows clients to specify the hostname during the initial handshake. This enables multiple websites to share the same IP address. However, traditional SNI sends this information in plain text, making it vulnerable to interception and tampering.

### From Plain SNI to ESNI

In response to privacy concerns, Encrypted SNI (ESNI) was developed and first drafted in 2018. ESNI encrypted the SNI information using a key derived from the server's certificate, preventing eavesdroppers from seeing which website a user was visiting.

### Evolution to ECH

In March 2020, ESNI was redesigned into Encrypted Client Hello (ECH) for TLS 1.3. Analysis showed that encrypting only SNI was insufficient because:

- Other TLS extensions (like Pre-Shared Key) could leak the same information in plain text
- Each extension would need its own encrypted variant, creating complexity
- Real-world ESNI deployment revealed interoperability issues

**ECH encrypts the entire Client Hello message**, not just the SNI. This provides comprehensive protection of all metadata in the initial TLS handshake, including:
- Server name (SNI)
- Supported cipher suites
- TLS extensions
- Application-layer protocol negotiation (ALPN)

### Technical Details

ECH works by:
1. Client fetches ECH configuration from DNS HTTPS records
2. Client encrypts the entire Client Hello using the public key from ECH config
3. Server decrypts the Client Hello with its private key
4. TLS handshake proceeds normally

ECH requires TLS 1.3 as it relies on KeyShareEntry introduced in that version. Clients must not propose TLS versions below 1.3 when using ECH.

### Current State

ECH is most effective with large CDNs whose configurations are known to browsers in advance. Not all servers support ECH - when unavailable, connections proceed with standard TLS 1.3 without ECH protection.

## References

- [Cloudflare - Encrypted SNI](https://blog.cloudflare.com/encrypted-sni/)
- [History of Encrypted SNI](https://www.e2encrypted.com/posts/history-of-encrypted-sni/)
- [Good-bye ESNI, hello ECH!](https://blog.cloudflare.com/encrypted-client-hello/)
- [Server Name Indication (wiki)](https://en.wikipedia.org/wiki/Server_Name_Indication)
- [Domain Fronting](https://en.wikipedia.org/wiki/Domain_fronting)
