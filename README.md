# CensorLab: A Generic Testbed for Censorship Emulation

**[Documentation](https://censorlab.cs.umass.edu/)** | **[Getting Started](https://censorlab.cs.umass.edu/getting_started/)** | **[API Reference](https://censorlab.cs.umass.edu/docs/)**

CensorLab is a censorship emulation testbed that intercepts network packets and processes them through configurable layers with optional Python scripts or ML models for custom censorship logic. See the [paper](https://arxiv.org/abs/2412.16349) for design and evaluation details.

## Quick Start (Docker)

```bash
git clone https://github.com/SPIN-UMass/censorlab.git
cd censorlab
git submodule update --init

# Interactive shell
./docker/censorlab.sh --shell

# Run all experiments
./experiments/scripts/run_all_docker.sh
```

## Building from Source

```bash
git clone https://github.com/SPIN-UMass/censorlab.git
cd censorlab
git submodule update --init
cargo build --release
sudo ./set_permissions.sh
```

Nix users: `nix develop` provides a complete environment.

## Running

```bash
# NFQ mode (live interception via netfilter queue)
censorlab -c censor.toml nfq

# PCAP mode (offline analysis)
censorlab -c censor.toml pcap capture.pcap 192.168.1.100

# With a script directly
censorlab -p censor.py nfq

# Help
censorlab --help
```

## Pre-built VM

Pre-built VirtualBox images with everything pre-installed are available for [x86_64](https://voyager.cs.umass.edu/vm-images/censorlab.ova) and [aarch64](https://voyager.cs.umass.edu/vm-images/censorlab-arm.vmdk). See the [VM setup guide](https://censorlab.cs.umass.edu/vm-info/) for import instructions.

This option requires manual updating and is not recommended outside of classroom setting.

## Experiments

Reproducible experiments for evaluation. See [`experiments/README.md`](experiments/README.md) for details.
