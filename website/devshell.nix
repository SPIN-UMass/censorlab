{ pkgs }:
pkgs.mkShell {
  nativeBuildInputs =
    let
      zola-serve = pkgs.writeShellScriptBin "zola-serve" ''
        #!/bin/sh
        ${pkgs.zola}/bin/zola --root $(${pkgs.git}/bin/git rev-parse --show-toplevel)/website serve
      '';
    in
    [
      pkgs.zola
      zola-serve
    ];
}
