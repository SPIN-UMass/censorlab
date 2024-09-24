{
  inputs = {
    nixpkgs.url = github:NixOS/nixpkgs/nixos-24.05;
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

  outputs = { self, nixpkgs, home-manager, utils, rust-overlay, crane, deploy-rs }:
    let
      overlays = [ (import rust-overlay) ];
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system overlays;
      };
      craneLib = (crane.mkLib pkgs).overrideToolchain (p: p.rust-bin.nightly.latest.default);
      onnxruntime = nixpkgs.legacyPackages."${system}".onnxruntime;
      # Library dependencies
      dependencies = [ onnxruntime pkgs.libffi ];
      # Native build inputs
      nativeBuildInputs = [ ];
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
      devShells."${system}".default = pkgs.mkShell ({
        nativeBuildInputs = nativeBuildInputs ++ [
          (pkgs.rust-bin.nightly.latest.default.override {
            extensions = [ "rust-src" "rustfmt" "rust-analyzer" "clippy" ];
          })
        ];
        buildInputs = [ ] ++ dependencies;
      } // onnx_vars);
      # Censorlab package
      packages.${system} = rec {
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
      # Censorlab overlay
      overlays = rec {
        default = censorlab;
        censorlab = final: prev: {
          censorlab = self.packages.${system}.censorlab;
          censorlab-vm-docs = self.packages.${system}.censorlab-vm-docs;
          censorlab-demos = self.packages.${system}.censorlab-demos;
        };
      };
      # System configuration for the VM
      nixosConfigurations.censorlab = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          {
            nixpkgs.overlays = [ self.overlays.default ];
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
            nixpkgs.overlays = [ self.overlays.default ];
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
          path = deploy-rs.lib.${system}.activate.nixos self.nixosConfigurations.censorlab;
        };
      };
      deploy.nodes.censorlab-arm = {
        # Deploy as root to localhost:10022 (set up as a port forward in the vm)
        sshUser = "root";
        hostname = "localhost";
        sshOpts = [ "-p" "10022" "-i" "./vm/id_ed25519" ];
        # Build locally rather than on the slow vm
        remoteBuild = true;
        fastConnection = false;
        # Deploy the censorlab system profile
        profiles.system = {
          user = "root";
          path = deploy-rs.lib.${system}.activate.nixos self.nixosConfigurations.censorlab-arm;
        };
      };

      # Perform checks
      checks = builtins.mapAttrs (system: deployLib: deployLib.deployChecks self.deploy) deploy-rs.lib;
    };
}
