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
  home-manager.backupFileExtension = true;
  # TODO: move the custom desktop shortcuts here
  # Needed for home-manager
  home.stateVersion = "24.05";
}
