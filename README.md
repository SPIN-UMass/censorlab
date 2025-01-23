# CensorLab: A Generic Testbed for Censorship Emulation

# About


# Recommended environment
Turn off offloading to entire accurate packet data
```
sudo ethtool -K eth0 tso off gro off gso off lro off
```

# Configuration
Configuration of the censor is done in `TOML` files and passed in with the `-c` flag. See `censor.toml` for configuration options. You probably want to copy censor.toml to your own config file and pass it in. See the demos folder for more information.

# Running in tap mode
```sh
cargo run --release --bin censorlab -- -c censor.toml nfq 
```
To list all the configurable options:
```sh
cargo run --release --bin censorlab -- --help
cargo run --release --bin censorlab -- nfq --help
```
