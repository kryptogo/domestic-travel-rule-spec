# Taiwan Domestic Travel Rule API Specification

An open API specification for implementing FATF Travel Rule compliance between Virtual Asset Service Providers (VASPs) operating within Taiwan (Republic of China).

## Overview

This specification defines the inter-VASP communication protocol for exchanging originator and beneficiary information as required by the Financial Action Task Force (FATF) Recommendation 16 (the "Travel Rule") for domestic virtual asset transfers.

### Key Features

- **Address Discovery** — Decentralized address ownership verification across domestic VASPs (no central registry required in Phase 1)
- **Encrypted PII Exchange** — RSA-OAEP / ECIES encryption of personal information with key rotation support
- **Anti-Replay Protection** — Nonce-based mechanism to prevent replay attacks
- **Memo/Tag Support** — Native support for chains requiring Memo or Destination Tag (XRP, Stellar, Cosmos, EOS)
- **Mutual Authentication** — HMAC-SHA256 request signing with optional mTLS

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/vasp/info` | Retrieve VASP information and public keys |
| `POST` | `/address/verify` | Verify address ownership |
| `POST` | `/transfer` | Submit Travel Rule data |
| `POST` | `/transfers/{id}/confirm` | Accept or reject a transfer |
| `GET` | `/transfers/{id}` | Query transfer status |
| `PATCH` | `/transfers/{id}` | Update transfer information (e.g., tx_hash) |
| `GET` | `/health` | Health check |

### Supported Networks

Bitcoin, Ethereum, Tron, BNB Smart Chain, Polygon, Arbitrum, Optimism, Solana, XRP Ledger, Stellar, Cosmos Hub, EOS

## Specification

The complete API specification is available in [`api-spec.md`](./api-spec.md).

**Current version**: 2.0 (2025-02-11)

## Documentation Site

This project uses [Mintlify](https://mintlify.com) for documentation. Engineers can preview locally:

```bash
# Install Mintlify CLI (requires Node.js >= 20.17.0)
npm install -g @mintlify/cli

# Start local dev server
mint dev
```

The documentation will be available at `http://localhost:3000`.

## Contributing

This is an open specification. All Taiwan-based VASPs and industry participants are encouraged to contribute.

- **Suggest changes**: Open an [Issue](https://github.com/kryptogo/domestic-travel-rule-spec/issues)
- **Submit modifications**: Create a [Pull Request](https://github.com/kryptogo/domestic-travel-rule-spec/pulls)
- **Discuss**: Join [GitHub Discussions](https://github.com/kryptogo/domestic-travel-rule-spec/discussions)

### Versioning

This specification follows semantic versioning. All changes are documented in the changelog section of [`api-spec.md`](./api-spec.md#變更紀錄).

## References

- [FATF Recommendation 16](https://www.fatf-gafi.org/recommendations.html)
- [TRISA Protocol](https://trisa.io/)
- [OpenVASP](https://openvasp.org/)
- [interVASP Messaging Standard (IVMS101)](https://intervasp.org/)

## License

This specification is published for public use. VASPs operating in Taiwan may implement this specification to comply with domestic Travel Rule requirements.

## Maintainers

Maintained by the [Taiwan Virtual Currency Commercial Association](https://www.facebook.com/TaiwanVirtualCurrencyAssociation/) (中華民國虛擬通貨商業同業公會) with technical support from [KryptoGO](https://kryptogo.com).
