{
  inputs = {
    nixpkgs.url = github:NixOS/nixpkgs/nixos-24.05;
    nixpkgs-master.url = github:NixOS/nixpkgs/master;
    home-manager = {
      url = github:nix-community/home-manager/release-24.05;
      inputs.nixpkgs.follows = "nixpkgs";
    };
    utils.url = github:numtide/flake-utils;
    crane.url = github:ipetkov/crane;
    rust-overlay = {
      url = github:oxalica/rust-overlay;
      inputs.nixpkgs.follows = "nixpkgs";
    };
    deploy-rs = {
      url = github:serokell/deploy-rs;
      inputs = {
        nixpkgs.follows = "nixpkgs";
        utils.follows = "utils";
      };
    };
  };

  outputs = { self, nixpkgs, home-manager, utils, rust-overlay, crane, deploy-rs, nixpkgs-master }:
    utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          pkgs-master = import nixpkgs-master {
            inherit system;
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain (p: p.rust-bin.nightly.latest.default);
          onnxruntime = pkgs-master.onnxruntime;
          # Library dependencies
          dependencies = [ onnxruntime pkgs.libffi ];
          # Native build inputs
          nativeBuildInputs = [ onnxruntime ];
          # Common arguments to building censorlab and deps
          onnx_vars = {
            ORT_STRATEGY = "system";
            ORT_LIB_LOCATION = "${onnxruntime}";
          };
          common_args = onnx_vars // {
            strictDeps = true;
            inherit nativeBuildInputs;
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
          devShells.default = pkgs.mkShell ({
            nativeBuildInputs = nativeBuildInputs ++ [
              (pkgs.rust-bin.nightly.latest.default.override {
                extensions = [ "rust-src" "rustfmt" "rust-analyzer" "clippy" ];
              })
            ];
            buildInputs = [ ] ++ dependencies;
          } // onnx_vars);
          # Censorlab package
          packages = rec {
            default = censorlab;
            # TODO: split scripts  out into a second derivation
            censorlab = craneLib.buildPackage (common_args // {
              # Install from source (remove all the extra stuff)
              src = pkgs.lib.cleanSourceWith {
                src = ./.;
                filter = path: _type: (craneLib.filterCargoSources path _type) ||
                builtins.match ".*lalrpop" path != null ||
                builtins.match ".*sh" path != null;
                name = "source";
              };
              # Dependencies
              inherit cargoArtifacts nativeBuildInputs;
              # Add extra scripts
              postInstall = ''
                mkdir -p $out/bin
                cp ./nftables.sh $out/bin/cl_nftables.sh
              '';
            });
            censorlab-vm-docs = pkgs.callPackage
              ({ stdenv, pandoc, ... }: stdenv.mkDerivation {
                pname = "censorlab-vm-docs";
                version = "0.1";
                src = ./vm/docs;
                nativeBuildInputs = [ pandoc ];
                installPhase = ''
                  mkdir -p $out/share/censorlab
                  pandoc -f gfm ./README.md > $out/share/censorlab/README.html
                '';
              })
              { };
            censorlab-demos = pkgs.callPackage
              ({ stdenv, pandoc, ... }: stdenv.mkDerivation {
                pname = "censorlab-demos";
                version = "0.1";
                src = ./demos;
                nativeBuildInputs = [ ];
                installPhase = ''
                  mkdir -p $out/share/censorlab-demos
                  cp -r ./* $out/share/censorlab-demos/
                '';
              })
              { };
          };
        }) // {
      # Censorlab overlay
      overlays = rec {
        censorlab = final: prev: {
          censorlab = self.packages.x86_64-linux.censorlab;
          censorlab-vm-docs = self.packages.x86_64-linux.censorlab-vm-docs;
          censorlab-demos = self.packages.x86_64-linux.censorlab-demos;
        };
        censorlab-arm = final: prev: {
          censorlab = self.packages.aarch64-linux.censorlab;
          censorlab-vm-docs = self.packages.aarch64-linux.censorlab-vm-docs;
          censorlab-demos = self.packages.aarch64-linux.censorlab-demos;
        };
      };
      # System configuration for the VM
      nixosConfigurations.censorlab = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          {
            nixpkgs.overlays = [ self.overlays.censorlab ];
          }
          (import ./vm/configuration.nix)
          (import ./vm/hardware-x8664.nix)
          home-manager.nixosModules.default
        ];
      };
      nixosConfigurations.censorlab-arm = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        modules = [
          {
            nixpkgs.overlays = [ self.overlays.censorlab-arm ];
          }
          (import ./vm/configuration.nix)
          (import ./vm/hardware-aarch64.nix)
          home-manager.nixosModules.default
        ];
      };
      # Deploy config
      deploy.nodes.censorlab = {
        # Deploy as root to localhost:2222 (set up as a port forward in the vm
        sshUser = "root";
        hostname = "localhost";
        sshOpts = [ "-p" "2222" "-i" "./vm/id_ed25519" ];
        # Build locally rather than on the slow vm
        remoteBuild = false;
        fastConnection = true;
        # Deploy the censorlab system profile
        profiles.system = {
          user = "root";
          path = deploy-rs.lib.x86_64-linux.activate.nixos self.nixosConfigurations.censorlab;
        };
      };
      deploy.nodes.censorlab-arm = {
        sshUser = "root";
        hostname = "167.235.134.18";
        #sshOpts = [ "./vm/id_ed25519" ];
        # build remotely because cross arch is weird 
        remoteBuild = true;
        fastConnection = false;
        # Deploy the censorlab system profile
        profiles.system = {
          user = "root";
          path = deploy-rs.lib.aarch64-linux.activate.nixos self.nixosConfigurations.censorlab-arm;
        };
      };

      # Perform checks
      checks = builtins.mapAttrs (system: deployLib: deployLib.deployChecks self.deploy) deploy-rs.lib;
    };
}
