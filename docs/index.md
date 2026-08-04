# AuthDiff

Deterministic differential authorization testing. AuthDiff detects broken access
control (BOLA/IDOR, BFLA, mass-assignment) and single-use race conditions using
cryptographic **canary oracles** that guarantee 0% false positives by construction.

- **Get started:** see the [README quickstart](https://github.com/bdalzyzr116-rgb/authdiff-bugbounty#quickstart).
- **How it works:** [Architecture](architecture.md).
- **Configure a run:** [Configuration](configuration.md).
- **Questions:** [FAQ](faq.md).

> Authorized use only. Every network command requires `--authorized`.
