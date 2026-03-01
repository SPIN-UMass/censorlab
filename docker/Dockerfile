FROM nixos/nix:latest

RUN mkdir -p /etc/nix && \
    echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf && \
    echo "filter-syscalls = false" >> /etc/nix/nix.conf && \
    echo "cores = 2" >> /etc/nix/nix.conf

WORKDIR /censorlab

# NOTE: censorlab.sh hashes the paths copied below to detect when a rebuild is
# needed. If you add, remove, or rename any COPY source paths, you MUST update
# the path list in compute_build_hash() in docker/censorlab.sh to match.

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
RUN nix develop .#experiments --command true

# Capture the shell environment so we can activate it at runtime without
# re-evaluating the flake (which would trigger a rebuild when experiments
# are bind-mounted with different content).
RUN nix print-dev-env .#experiments > /dev-env.sh

# Copy experiments last — changes here only rebuild this cheap layer
COPY experiments/ experiments/

# Copy website source and build with zola (anonymous mode for review)
COPY website/ website/
RUN sed -i 's/^anonymous = false/anonymous = true/' website/config.toml && \
    sed -i '/arxiv\.org/d' website/content/getting_started/_index.md && \
    sed -i 's|https://github.com/SPIN-UMass/censorlab/tree/main/demos/model|/docs/#pycl-python-censor-language-reference|g' website/content/getting_started/_index.md && \
    sed -i 's|https://github.com/SPIN-UMass/censorlab/tree/main/demos|/docs/|g' website/content/getting_started/_index.md website/content/docs.md && \
    sed -i 's|https://github.com/SPIN-UMass/censorlab\.git|https://anonymous.example.com/censorlab.git|g' website/content/docs.md website/content/getting_started/_index.md && \
    sed -i 's|https://github.com/SPIN-UMass/censorlab|/docs/|g' website/content/docs.md && \
    sed -i 's|https://voyager.cs.umass.edu/vm-images/|https://anonymous.example.com/vm-images/|g' website/content/vm-info/_index.md && \
    source /dev-env.sh && cd website && zola build --base-url http://localhost:1116

# MOTD shown on interactive shell startup
RUN printf '\n\033[1mCensorLab\033[0m — A Generic Testbed for Censorship Emulation\n\nDocs:           http://localhost:1116/getting_started/\nDocumentation:  http://localhost:1116/docs/\nDemos:          ls demos/\nHelp:           censorlab --help\n\n' > /etc/motd

# Build fingerprint — passed by censorlab.sh to detect when rebuilds are needed.
# Must be last so it doesn't invalidate earlier cached layers.
ARG BUILD_HASH=""
LABEL censorlab.build_hash="${BUILD_HASH}"

ENTRYPOINT ["bash", "-c", "source /dev-env.sh && { if [ \"$1\" = bash ] && [ $# -eq 1 ] && [ -t 0 ]; then python3 -m http.server 1116 --bind 0.0.0.0 -d /censorlab/website/public &>/dev/null & cat /etc/motd; fi; exec \"$@\"; }", "--"]
CMD ["bash"]
