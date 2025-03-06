# Configuration

Glutton’s behavior is controlled by several configuration files written in YAML (and JSON for schema validation). This page details the available configuration options, how they’re loaded, and best practices for customizing your setup. 

## Configuration Files

### config/config.yaml

This file holds the core settings for Glutton. Key configuration options include:

- **ports:** Defines the network ports used for traffic interception.
  - **tcp:** The TCP port for intercepted connections (default: `5000`).
  - **udp:** The UDP port for intercepted packets (default: `5001`).
  - **ssh:** Typically excluded from redirection to avoid interfering with SSH (default: `22`).
- **interface:** The network interface Glutton listens on (default: `eth0`).
- **max_tcp_payload:** Maximum TCP payload size in bytes (default: `4096`).
- **conn_timeout:** The connection timeout duration in seconds (default: `45`).
- **confpath:** The directory path where the configuration file resides.
- **producers:** 
    - **enabled**: Boolean flag to enable or disable logging/producer functionality.
    - **http:** HTTP producer for sending logs to a remote endpoint, like [Ochi](https://github.com/honeynet/ochi).
    - **hpfeeds:** [HPFeeds](https://github.com/hpfeeds/hpfeeds) producer for sharing data with other security tools.
- **addresses:** A list of additional public IP addresses for traffic handling.

Example configuration:

```yaml
# config/config.yaml

ports:
  tcp: 5000
  udp: 5001
  ssh: 22

rules_path: config/rules.yaml

addresses: ["1.2.3.4"]

interface: eth0

producers:
  enabled: true # enables producers
  http:
    enabled: true # enables http producer
    # Connect with Ochi here or other remote log aggregation servers 
    remote: http://localhost:3000/publish?token=token 
  hpfeeds:
    enabled: false # disables HPFeeds
    host: 172.26.0.2
    port: 20000
    # HPFeeds specific details go here
    ident: ident
    auth: auth
    channel: test

conn_timeout: 45
max_tcp_payload: 4096
```

### config/rules.yaml

This file defines the rules that Glutton uses to determine which protocol handler should process incoming traffic.

Key elements include:

- **type**: `conn_handler` to pass off to the appropriate protocol handler or `drop` to ignore packets.
- **target**: Indicates the protocol handler (e.g., "http", "ftp") to be used.
- **match**: Define criteria such as source IP ranges or destination ports to match incoming traffic, according to [BPF syntax](https://biot.com/capstats/bpf.html).

Example rule:

```yaml
# config/rules.yaml

rules:
  - name: Telnet filter
    match: tcp dst port 23 or port 2323 or port 23231
    type: conn_handler # will find the appropriate target protocol handler
    target: telnet
  - match: tcp dst port 6969
    type: drop # drops any matching packets
    target: bittorrent
```

## Configuration Loading Process
Glutton uses the [Viper](https://github.com/spf13/viper) library to load configuration settings. The process works as follows:

- **Default Settings**: Glutton initializes with default values for critical parameters.
- **File-based Overrides**: Viper looks for `config.yaml` in the directory specified by confpath. If found, the settings from the file override the defaults.
- **Additional Sources**: Environment variables or command-line flags can further override file-based configurations, allowing for flexible deployments.

## Best Practices

- **Backup Your Files**: Always save a backup of your configuration files before making changes.
- **Validate Configurations**: Use YAML validators and the provided JSON schema to ensure your configuration is error-free.
- **Test Changes**: After modifying your configuration, restart Glutton and review the logs to confirm that your changes have been applied as expected.
