FROM nixos/nix:latest

RUN mkdir -p /etc/nix && \
    echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf && \
    echo "filter-syscalls = false" >> /etc/nix/nix.conf

WORKDIR /censorlab

# Copy flake inputs first (best layer caching)
COPY flake.nix flake.lock ./

# Copy Cargo manifests + build script (Rust dep layer)
COPY Cargo.toml Cargo.lock build.rs ./

# Copy Rust source
COPY src/ src/

# Copy demos (referenced by build/configs)
COPY demos/ demos/

# Materialize the experiments shell (expensive, cached by Docker layers).
# This must come BEFORE copying experiments so that editing experiment
# scripts doesn't invalidate the Nix build cache.
RUN nix develop .#experiments --profile /nix/var/nix/profiles/experiments --command true

# Copy experiments last — changes here only rebuild this cheap layer
COPY experiments/ experiments/

ENTRYPOINT ["nix", "develop", ".#experiments", "--command"]
CMD ["bash"]
