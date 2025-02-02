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

Build glutton:
```
make build
```

To run/test glutton:
```
bin/server
```

To get this to work on WSL, use this kernel: https://github.com/Locietta/xanmod-kernel-WSL2

Here’s a rephrased version:

### Setting Up the Dev Environment with VS Code Dev Container

First, install the Dev Container extension. To learn more about setting up and using dev containers, check out the following resources:  
- [Install Dev Container](https://code.visualstudio.com/docs/devcontainers/containers)  
- [Learn More](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
