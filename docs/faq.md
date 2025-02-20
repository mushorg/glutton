# Frequently Asked Questions

### Q: What is Glutton?
**A:** Glutton is a protocol-agnostic honeypot that intercepts network traffic, applies customizable rules, and logs interactions to help analyze malicious activities.

### Q: Which protocols does Glutton support?
**A:** Out of the box, Glutton supports multiple protocols via its TCP and UDP handlers. The repository includes handlers for protocols such as HTTP, FTP, SMTP, Telnet, MQTT, and more. You can extend support to additional protocols as needed.

### Q: How do I add a new protocol or extend existing functionality?
**A:** You can add a new protocol handler by implementing the appropriate interface in the `protocols/` directory and registering your handler in the corresponding mapping function. See the [Extension](extension.md) section for detailed instructions.

### Q: How do I configure Glutton?
**A:** Configuration is managed through YAML files:
- **config/config.yaml:** General settings such as port numbers and interface names.
- **config/rules.yaml:** Defines rules for matching and processing network traffic.

### Q: What are the system prerequisites?
**A:** Glutton requires a Linux system, so if you're using a different OS, you'll have to use Docker to set it up. Specific installation commands are provided in the [Setup](setup.md) section.
