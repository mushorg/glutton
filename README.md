# Glutton
![Tests](https://github.com/mushorg/glutton/actions/workflows/workflow.yml/badge.svg)
[![GoDoc](https://godoc.org/github.com/mushorg/glutton?status.svg)](https://godoc.org/github.com/mushorg/glutton)

Setup `go 1.21`. 

Install required system packages:

Debian:
```
apt-get install gcc libpcap-dev iptables
```

Arch:
```
pacman -S gcc libpcap iptables
```

Fedora:
```
sudo dnf install gcc libpcap-devel iptables
```

Build glutton:
```
make build
```

To run/test glutton:
```
sudo bin/server
```

To get this to work on WSL, use this kernel: https://github.com/Locietta/xanmod-kernel-WSL2

### Setting up the Dev Container environment with VS Code

Since this project requires a Linux environment to build and run, you need to use a Docker container on other operating systems. For development, we recommend using the Dev Container Extension for VS Code.

First, install the Dev Container extension. To learn more about setting up and using dev containers, check out the following resources:  
- [Install Dev Container](https://code.visualstudio.com/docs/devcontainers/containers)  
- [Learn More](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
