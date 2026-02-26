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
    utils.lib.eachDefaultSystem
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
              pkgs.tcpdump
              pkgs.curl
              pkgs.dnsutils
              pkgs.iptables
              pkgs.coreutils
              pkgs.bash
              pkgs.time
              pkgs.zola
            ];
          };
          devShells.website = import ./website/devshell.nix { inherit pkgs; };
          # Censorlab package
          packages = rec {
            default = censorlab;
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
        }) // (if builtins.pathExists ./vm/outputs.nix
              then import ./vm/outputs.nix { inherit self nixpkgs home-manager deploy-rs; }
              else {});
}
