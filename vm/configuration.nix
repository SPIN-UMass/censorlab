# Edit this configuration file to define what should be installed on
# your system. Help is available in the configuration.nix(5) man page, on
# https://search.nixos.org/options and in the NixOS manual (`nixos-help`).

{ config, lib, pkgs, ... }:
let
  ssh_pubkey = builtins.readFile ./id_ed25519.pub;
  censorlab-demos = pkgs.censorlab-demos;
in
{
  imports =
    [
    ];
  nixpkgs.config.allowUnfree = true;
  # Use the systemd-boot EFI boot loader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.kernelModules = [ "xt_NFQUEUE" ];
  networking.hostName = "censorlab"; # Define your hostname.
  # Pick only one of the below networking options.
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.
  # networking.networkmanager.enable = true;  # Easiest to use and most distros use this by default.

  # Set your time zone.
  time.timeZone = "UTC";

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Select internationalisation properties.
  i18n.defaultLocale = "en_US.UTF-8";

  # Nix stuff
  nix = {
    # Use flakes
    package = pkgs.nixFlakes;
    # Garbage collect
    gc = {
      automatic = true;
      persistent = true;
      options = "--delete-older-than 7d";
    };
    # Other settings
    settings = {
      sandbox = true;
      auto-optimise-store = true;
      experimental-features = [ "nix-command" "flakes" "auto-allocate-uids" ];
      auto-allocate-uids = true;
    };
  };
  # Random stuff
  boot.tmp.cleanOnBoot = true;

  # Enable the X11 windowing system.
  services.xserver = {
    enable = true;
    # Use KDE
    desktopManager.plasma5 = {
      enable = true;
    };
  };
  # Cut out a bunch of the default packages
  environment.plasma5.excludePackages = with pkgs.plasma5Packages; [
    ark
    elisa
    gwenview
    okular
    khelpcenter
    print-manager
  ];
  # Autologin into censorlab
  services.displayManager.autoLogin = {
    enable = true;
    user = "censorlab";
  };

  # Use mutable users
  users.mutableUsers = false;
  # Main user account
  users.users.censorlab = {
    isNormalUser = true;
    extraGroups = [ "wheel" ]; # Enable ‘sudo’ for the user.
    # Password
    hashedPassword = "$6$rounds=10000$8xHqgl3MIbGTLIzO$Xzf2Re55hgFZwUlO0vS.BO7ykbQmc6aggC2uJ88Ao.MJeTHHH.MMu5/6Lrjdfdp1SMShkXtkRXWXDGxX8Wd4l1";
    # SSH public key
    openssh.authorizedKeys.keys = [ ssh_pubkey ];
  };
  # Root login details
  users.users.root = {
    hashedPassword = "$6$rounds=10000$DDn28JVK1Gya9RmU$AoQkLDJ0CGVu.3Fua1/G4W.7TAPLfGQUfIIbj6fmnpETI7cY/ggeNwVMhREAc4mFLtX3z7Bg7y9eh.euF5fNF0";
    openssh.authorizedKeys.keys = [ ssh_pubkey ];
  };

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
    wget
    tmux
    # for flake
    git
    # For demo stuff
    curl
    bind
    shadowsocks-rust
    # Install censorlab
    censorlab
    censorlab-demos
    censorlab-update
  ];
  # Path to demos system wide
  # Give access to demos
  environment.etc."censorlab-demos" = {
    source = "${censorlab-demos}/share/censorlab-demos";
  };

  # Enable the OpenSSH daemon.
  services.openssh.enable = true;
  services.openssh.openFirewall = true;
  services.openssh.settings.PermitRootLogin = "yes";

  # Enable the firewall
  networking.firewall.enable = true;

  # Enable censorlab
  security.wrappers.censorlab = {
    source = "${pkgs.censorlab}/bin/censorlab";
    owner = "root";
    group = "wheel";
    capabilities = "cap_net_admin,cap_net_raw+eip";
  };
  # Home manager stuff
  home-manager = {
    useGlobalPkgs = true;
    useUserPackages = true;
    users.censorlab = (import ./home.nix);
  };
  # This option defines the first version of NixOS you have installed on this particular machine,
  # and is used to maintain compatibility with application data (e.g. databases) created on older NixOS versions.
  #
  # Most users should NEVER change this value after the initial install, for any reason,
  # even if you've upgraded your system to a new NixOS release.
  #
  # This value does NOT affect the Nixpkgs version your packages and OS are pulled from,
  # so changing it will NOT upgrade your system - see https://nixos.org/manual/nixos/stable/#sec-upgrading for how
  # to actually do that.
  #
  # This value being lower than the current NixOS release does NOT mean your system is
  # out of date, out of support, or vulnerable.
  #
  # Do NOT change this value unless you have manually inspected all the changes it would make to your configuration,
  # and migrated your data accordingly.
  #
  # For more information, see `man configuration.nix` or https://nixos.org/manual/nixos/stable/options#opt-system.stateVersion .
  system.stateVersion = "24.05"; # Did you read the comment?

}

