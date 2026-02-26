{ self, nixpkgs, home-manager, deploy-rs }:
{
  # Censorlab overlay
  overlays = rec {
    censorlab = final: prev: {
      censorlab = self.packages.x86_64-linux.censorlab;
      censorlab-vm-docs = self.packages.x86_64-linux.censorlab-vm-docs;
      censorlab-demos = self.packages.x86_64-linux.censorlab-demos;
      censorlab-update = self.packages.x86_64-linux.censorlab-update;
    };
    censorlab-arm = final: prev: {
      censorlab = self.packages.aarch64-linux.censorlab;
      censorlab-vm-docs = self.packages.aarch64-linux.censorlab-vm-docs;
      censorlab-demos = self.packages.aarch64-linux.censorlab-demos;
      censorlab-update = self.packages.aarch64-linux.censorlab-update-arm;
    };
  };
  # System configuration for the VM
  nixosConfigurations.censorlab = nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      {
        nixpkgs.overlays = [ self.overlays.censorlab ];
        nixpkgs.config.allowUnfree = true;
      }
      (import ./configuration.nix)
      (import ./hardware-x8664.nix)
      home-manager.nixosModules.default
    ];
  };
  nixosConfigurations.censorlab-arm = nixpkgs.lib.nixosSystem {
    system = "aarch64-linux";
    modules = [
      {
        nixpkgs.overlays = [ self.overlays.censorlab-arm ];
        nixpkgs.config.allowUnfree = true;
      }
      (import ./configuration.nix)
      (import ./hardware-aarch64.nix)
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
    sshOpts = [ "-i" "./vm/id_ed25519" ];
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
}
