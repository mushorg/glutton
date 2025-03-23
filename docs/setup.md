# Setup

Follow these steps to install Glutton on your system.

## Environment Requirements


- **Linux Required:** Glutton must be built and run on a Linux system.
- **Non-Linux Users:** For Windows or macOS, use Docker or the VSCode Dev Container Extension.
- **WSL Users:** When using WOS, we recommend running glutton with the [xanmod-kernel-WSL2](https://github.com/Locietta/xanmod-kernel-WSL2)
- For setting up the development environment using VS Code Dev Containers, refer to:
    - [Install Dev Container](https://code.visualstudio.com/docs/devcontainers/containers)  
    - [Learn More](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

## Prerequisites

Ensure you have [Go](https://go.dev/dl/) installed (recommended version: **Go 1.21** or later). In addition, you will need system packages for building and running Glutton:

### Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install gcc libpcap-dev iptables
```

### Arch Linux
```bash
sudo pacman -S gcc libpcap iptables
```

### Fedora
```bash
sudo dnf install gcc libpcap-devel iptables
```

## Building Glutton

Clone the repository and build the project:

```bash
git clone https://github.com/mushorg/glutton.git
cd glutton
make build
```

This will compile the project and place the server binary in the `bin/` directory.

## Testing the Installation

```bash
bin/server --version
```
Replace `<network_interface>` (e.g., `eth0`) with the interface you want to monitor. You should see output similar to:

```bash
  _____ _       _   _
 / ____| |     | | | |
| |  __| |_   _| |_| |_ ___  _ __
| | |_ | | | | | __| __/ _ \| '_ \
| |__| | | |_| | |_| || (_) | | | |
 \_____|_|\__,_|\__|\__\___/|_| |_|

	
glutton version v1.0.1+d2503ba 2025-02-21T05:48:07+00:00
```

## Usage

Glutton can be configured using several command-line flags:

- **--interface, -i**: `string` - Specifies the network interface (default: `eth0`)
- **--ssh, -s**: `int` - If set, it overrides the default SSH port
- **--logpath, -l**: `string` - Sets the file path for logging (default: `/dev/null`)
- **--confpath, -c**: `string` - Defines the path to the configuration directory (default: `config/`)
- **--debug, -d**: `bool` - Enables debug mode (default: `false`)
- **--version**: `bool` - Prints the version and exits
- **--var-dir**: `string` - Sets the directory for variable data storage (default: `/var/lib/glutton`)

For example, to run Glutton with a custom interface and enable debug mode, you might use the following command:

```bash
bin/server --interface <network_interface> --debug
```

Replace `<network_interface>` (e.g., `eth0`) with the interface you want to monitor. The command starts the Glutton server, which sets up TCP/UDP listeners and applies iptables rules for transparent proxying.

**Configuration:** Before deployment, ensure your configuration files, in the `config/` folder by default, are properly set up. For detailed instructions, refer to the [Configuration](configuration.md) page.

## Docker

To deploy using Docker:

1. Build the Docker image:
   
    ```
    docker build -t glutton .
    ```

2. Run the Container:
   
    ```
    docker run --rm --cap-add=NET_ADMIN -it glutton
    ```

The Docker container is preconfigured with the necessary dependencies (iptables, libpcap, etc.) and copies the configuration and rules files into the container.

