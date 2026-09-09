# Security

This project includes an experimental local tool gateway and offline investigator. Use synthetic or sanitized data during development. Do not commit organization telemetry, credentials, databases, reports or environment files.

The gateway reads, queues exports of, and can delete local SQLite documents. It has no production connector or network sender. See `docs/GATEWAY.md` for its security boundary and production prerequisites.

Report vulnerabilities through GitHub private vulnerability reporting if enabled, otherwise contact the repository owner privately. Do not publish secrets in issues. Establish a reporting address and response policy before production adoption.
