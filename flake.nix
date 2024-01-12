{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
    utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nmattia/naersk/master";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, utils, rust-overlay, naersk }:
    let
      overlays = [ (import rust-overlay) ];
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system overlays;
      };
      rust_stable = pkgs.rust-bin.stable.latest.default;
      naersk' = pkgs.callPackage naersk { rustc = rust_stable; cargo = rust_stable; };
      onnxruntime = nixpkgs.legacyPackages."${system}".onnxruntime;
      dependencies = [ onnxruntime ];
      nativeBuildInputs = [ ];
    in
    {
      devShells."${system}".default =
        with pkgs;
        mkShell {
          inherit nativeBuildInputs;
          ORT_STRATEGY = "system";
          ORT_LIB_LOCATION = "${onnxruntime}";
          buildInputs = [
            rust_stable
          ] ++ dependencies;
        };
    };
}
