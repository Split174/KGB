{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.go
    pkgs.gopls
    pkgs.gotools
    pkgs.clang
    pkgs.llvm
    pkgs.elfutils
    pkgs.linuxHeaders
  ];

  shellHook = ''
    export BPF_CLANG=${pkgs.clang}/bin/clang
    export BPF_CFLAGS="-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include"
    export GOPATH=$(pwd)/go
    export PATH=$GOPATH/bin:$PATH
  '';
}