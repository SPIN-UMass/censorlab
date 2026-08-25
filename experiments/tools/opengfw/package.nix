# OpenGFW — "DIY Great Firewall" DPI engine (Go), used as a comparison point
# in Table 4 (meta-review item MR1).
#
# The upstream repository (apernet/OpenGFW) was deleted in 2025; this pins a
# complete fork of the final upstream tree (v0.4.x line, Oct 2024), which
# includes the `--pcap` replay mode used by the experiments harness.
{ lib, buildGoModule, fetchFromGitHub, libpcap }:

buildGoModule rec {
  pname = "opengfw";
  version = "0.4.1-unstable-2024-10-27";

  src = fetchFromGitHub {
    owner = "tanaka0722-dev";
    repo = "OpenGFW";
    rev = "169a938d61f7b115dfe32cee2d81e5ccedea958f";
    hash = "sha256-6PFfsPfLzzeaImcteX9u/k5pwe3cvSQwT90TCizA3gI=";
  };

  vendorHash = "sha256-F8jTvgxOhOGVtl6B8u0xAIvjNwVjBtvAhApzjIgykpY=";

  buildInputs = [ libpcap ];

  # Tests need network / nfqueue
  doCheck = false;

  ldflags = [ "-s" "-w" ];

  meta = with lib; {
    description = "Flexible, easy-to-use, open source implementation of GFW on Linux";
    homepage = "https://github.com/tanaka0722-dev/OpenGFW";
    license = licenses.mpl20;
    mainProgram = "OpenGFW";
    platforms = platforms.linux;
  };
}
