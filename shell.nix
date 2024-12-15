{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  buildInputs = [
    pkgs.go
    pkgs.gopls
    pkgs.gotools
    pkgs.wget
    pkgs.nftables
  ];
}
