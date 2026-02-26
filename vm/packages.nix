{ pkgs }:
{
  # Helper scripts (set_permissions.sh, etc.) packaged separately from the binary
  censorlab-scripts = pkgs.callPackage
    ({ stdenv, ... }: stdenv.mkDerivation {
      pname = "censorlab-scripts";
      version = "0.1";
      src = pkgs.lib.cleanSourceWith {
        src = ./..;
        filter = path: _type: builtins.match ".*\\.sh" path != null;
        name = "scripts-source";
      };
      installPhase = ''
        mkdir -p $out/bin
        for f in *.sh; do
          [ -f "$f" ] && install -m755 "$f" "$out/bin/"
        done
      '';
    })
    { };
  censorlab-vm-docs = pkgs.callPackage
    ({ stdenv, pandoc, ... }: stdenv.mkDerivation {
      pname = "censorlab-vm-docs";
      version = "0.1";
      src = ./docs;
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
      src = ../demos;
      nativeBuildInputs = [ ];
      installPhase = ''
        mkdir -p $out/share/censorlab-demos
        cp -r ./* $out/share/censorlab-demos/
      '';
    })
    { };

  censorlab-update = pkgs.writeShellScriptBin "censorlab-update" ''
    nix-collect-garbage -d
    nixos-rebuild switch --flake github:SPIN-UMass/censorlab#censorlab --use-remote-sudo
    sudo /nix/var/nix/profiles/system/bin/switch-to-configuration switch
  '';
  censorlab-update-arm = pkgs.writeShellScriptBin "censorlab-update" ''
    nix-collect-garbage -d
    nixos-rebuild switch --flake github:SPIN-UMass/censorlab#censorlab-arm --use-remote-sudo
    sudo /nix/var/nix/profiles/system/bin/switch-to-configuration switch
  '';
}
