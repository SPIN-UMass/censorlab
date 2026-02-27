# CensorLab VM

This directory contains the NixOS configuration for the CensorLab virtual machine.

For full documentation, see **[censorlab.cs.umass.edu](https://censorlab.cs.umass.edu/)**.

## Credentials

| | |
|---|---|
| **Username** | `censorlab` |
| **Password** | `c3ns0rl4b612@@!` |

## VM Downloads

- **x86_64**: [censorlab.ova](https://voyager.cs.umass.edu/vm-images/censorlab.ova) (import directly into VirtualBox)
- **aarch64** (Apple Silicon): [censorlab-arm.vmdk](https://voyager.cs.umass.edu/vm-images/censorlab-arm.vmdk) (import as a drive; see [setup guide](https://censorlab.cs.umass.edu/vm-info/))

## Usage

The desktop has shortcuts to the documentation and a terminal. CensorLab is pre-installed and on your `PATH`:

```bash
censorlab -c demos/dns_blocking/censor.toml nfq
```

See the [Getting Started guide](https://censorlab.cs.umass.edu/getting_started/) for a full walkthrough, and the [API Reference](https://censorlab.cs.umass.edu/docs/) for configuration, PyCL, CensorLang, and protocol parser documentation.

## Updating

```bash
censorlab-update
```

This declaratively rebuilds the NixOS system to the latest CensorLab version. No data is lost.

## NixOS Configuration (for developers)

| File | Purpose |
|------|---------|
| `configuration.nix` | Main NixOS system configuration |
| `home.nix` | Home Manager config (desktop shortcuts, user environment) |
| `packages.nix` | CensorLab package definition |
| `outputs.nix` | Nix flake outputs for VM images |
| `hardware-x8664.nix` | x86_64 hardware config |
| `hardware-aarch64.nix` | aarch64 hardware config |
