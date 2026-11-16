{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    home-manager = {
      url = "github:nix-community/home-manager/release-25.11";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    deploy-rs = {
      url = "github:serokell/deploy-rs";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        utils.follows = "utils";
      };
    };
  };

  outputs = { self, nixpkgs, home-manager, utils, rust-overlay, crane, deploy-rs }:
    # recursiveUpdate so vm/outputs.nix deploy checks merge with ours per system
    nixpkgs.lib.recursiveUpdate (utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain (p: p.rust-bin.nightly.latest.default);
          # Library dependencies
          dependencies = [ pkgs.libffi ];
          # Common arguments to building censorlab and deps
          common_args = {
            strictDeps = true;
            buildInputs = dependencies;
          };
          # Build just the dependencies, without any of the extra stuff
          # Pulls from a clean cargo repo so it doesnt get updated when e.g. scripts or documentation get updated
          cargoArtifacts = craneLib.buildDepsOnly (common_args // {
            src = craneLib.cleanCargoSource ./.;
            # Additional arguments specific to this derivation can be added here.
            # Be warned that using `//` will not do a deep copy of nested
            # structures
            pname = "censorlab-deps";
          });
        in
        {
          # Shell used for developing censorlab
          devShells.default = pkgs.mkShell {
            nativeBuildInputs = [
              (pkgs.rust-bin.nightly.latest.default.override {
                extensions = [ "rust-src" "rustfmt" "rust-analyzer" "clippy" ];
              })
              pkgs.zola
            ];
            buildInputs = dependencies;
          };
          # Shell for running experiments (Table 3/4 in PoPETs paper)
          devShells.experiments = pkgs.mkShell {
            nativeBuildInputs = [
              self.packages.${system}.censorlab
              (pkgs.python3.withPackages (ps: with ps; [
                scapy
                pandas
                matplotlib
                scikit-learn
                onnx
                onnxruntime
                skl2onnx
              ]))
              pkgs.zeek
              pkgs.suricata
              pkgs.snort
              self.packages.${system}.opengfw
              pkgs.tcpdump
              pkgs.curl
              pkgs.dnsutils
              pkgs.iptables
              pkgs.coreutils
              pkgs.bash
              pkgs.time
              pkgs.zola
              pkgs.gnused
            ];
          };
          devShells.website = import ./website/devshell.nix { inherit pkgs; };
          # Censorlab package
          # Build-artifact-free test/lint runs: `nix build .#checks.<system>.tests`
          checks =
            let
              # Integration tests load demo configs, so include demos/ and tests/
              testSrc = pkgs.lib.fileset.toSource {
                root = ./.;
                fileset = pkgs.lib.fileset.unions [
                  (craneLib.fileset.commonCargoSources ./.)
                  (pkgs.lib.fileset.fileFilter (f: f.hasExt "lalrpop") ./src)
                  ./tests
                  ./demos
                ];
              };
              checkArgs = common_args // {
                src = testSrc;
                inherit cargoArtifacts;
              };
            in
            {
              tests = craneLib.cargoTest checkArgs;
              tests-wire = craneLib.cargoTest (checkArgs // { cargoTestExtraArgs = "--features wire"; });
              clippy = craneLib.cargoClippy (checkArgs // { cargoClippyExtraArgs = "--all-targets --all-features -- --deny warnings"; });
            };
          packages = rec {
            default = censorlab;
            # OpenGFW comparison tool for the Table 4 experiments (MR1)
            opengfw = pkgs.callPackage ./experiments/tools/opengfw/package.nix { };
            # Small Docker image (censorlab + iptables + iperf3 + python3) used by
            # experiments/10_nfq_end_to_end and docker/docker-compose.live.yml.
            # Build with `nix build .#docker-live` and `docker load < result`.
            docker-live = pkgs.dockerTools.buildLayeredImage {
              name = "censorlab-live";
              tag = "latest";
              contents = with pkgs; [
                censorlab
                bashInteractive
                coreutils
                gnugrep
                gnused
                iptables
                iproute2
                iperf3
                curl
                procps
                python3
                tcpdump
                cacert
              ];
              # iperf3 needs a writable /tmp
              extraCommands = "mkdir -m 1777 -p tmp";
              config = {
                Cmd = [ "/bin/bash" ];
                Env = [ "PATH=/bin" "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
              };
            };
            # Image with real circumvention tools (Shadowsocks, obfs4/lyrebird, Snowflake)
            # used by experiments/11_resilience_matrix to record genuine traffic.
            docker-circumvention = pkgs.dockerTools.buildLayeredImage {
              name = "censorlab-circumvention";
              tag = "latest";
              contents = with pkgs; [
                bashInteractive coreutils gnugrep gnused procps iproute2 curl cacert
                python3 tcpdump shadowsocks-rust obfs4 snowflake
              ];
              extraCommands = "mkdir -m 1777 -p tmp";
              config = {
                Cmd = [ "/bin/bash" ];
                Env = [ "PATH=/bin" "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt" ];
              };
            };
            censorlab = craneLib.buildPackage (common_args // {
              # Install from source (remove all the extra stuff)
              src = pkgs.lib.cleanSourceWith {
                src = ./.;
                filter = path: _type: (craneLib.filterCargoSources path _type) ||
                builtins.match ".*lalrpop" path != null;
                name = "source";
              };
              # Dependencies
              inherit cargoArtifacts;
              # Integration tests reference demo scripts not in the clean source
              doCheck = false;
            });
          } // (if builtins.pathExists ./vm/packages.nix
               then import ./vm/packages.nix { inherit pkgs; }
               else {});
        })) (if builtins.pathExists ./vm/outputs.nix
              then import ./vm/outputs.nix { inherit self nixpkgs home-manager deploy-rs; }
              else {});
}
