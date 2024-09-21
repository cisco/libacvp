{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];
      perSystem = { config, self', pkgs, lib, system, ... }:
        let
          devDeps = with pkgs; [ gcc gdb gnumake criterion doxygen ];
          buildDeps = with pkgs; [ curl openssl ];

          libacvp = pkgs.stdenv.mkDerivation {
            pname = "libacvp";
            version = "2.1.1";
            src = ./.;

            nativeBuildInputs = buildDeps;

            configureFlags = [
              "--with-ssl-dir=${pkgs.openssl.dev}"
              "--with-libcurl-dir=${pkgs.curl.dev}"
            ];
          };
        in rec {
          _module.args.pkgs = import inputs.nixpkgs { inherit system; };

          packages.default = libacvp;

          devShells.default =
            pkgs.mkShell { nativeBuildInputs = devDeps ++ buildDeps; };
        };
    };
}
