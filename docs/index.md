# Introduction

Glutton is a protocol-agnostic honeypot designed to emulate various network services and protocols. It is built in Go and aims to capture and analyze malicious network activity by intercepting connections and logging detailed interaction data. Glutton is highly configurable, allowing users to define custom rules and extend its functionality by adding new protocol handlers.

Key features include:

- **Protocol Agnostic:** Supports TCP and UDP traffic across a variety of protocols.
- **Rule-Based Processing:** Uses configurable rules to determine how incoming connections are handled.
- **Extensibility:** Easily extend the tool by adding new protocol handlers.
- **Logging and Analysis:** Captures connection metadata and payloads for further analysis.

This documentation will guide you through the installation, deployment, understanding its network interactions, extending its functionality, and addressing common questions.

