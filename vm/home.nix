{ pkgs, ... }:
let
  censorlab-docs = pkgs.censorlab-vm-docs;
in
{
  # Add docs
  home.packages = [ censorlab-docs ];
  # Set censorlab docs to firefox homepage
  programs.firefox = {
    enable = true;
    profiles."censorlab.default" = {
      isDefault = true;
      settings = {
        "browser.startup.homepage" = "file://${censorlab-docs}/share/censorlab/README.html";
      };
    };
  };
  # Desktop shortcuts
  xdg.desktopEntries = {
    censorlab-docs = {
      name = "CensorLab Docs";
      comment = "Open CensorLab documentation in Firefox";
      exec = "${pkgs.firefox}/bin/firefox file://${censorlab-docs}/share/censorlab/README.html";
      icon = "text-html";
      terminal = false;
      categories = [ "Documentation" ];
    };
    censorlab-demos = {
      name = "CensorLab Demos";
      comment = "Open a terminal in the demos directory";
      exec = "${pkgs.kdePackages.konsole}/bin/konsole --workdir /etc/censorlab-demos";
      icon = "utilities-terminal";
      terminal = false;
      categories = [ "Development" ];
    };
  };
  # Needed for home-manager
  home.stateVersion = "24.05";
}
