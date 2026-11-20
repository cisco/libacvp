{
  description = "libacvp package";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-26.05";
  };

  outputs = { self, nixpkgs, ... }:
  let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
  in {
    packages.${system} = rec {
      default = pkgs.stdenv.mkDerivation {
        name = "libacvp";

        buildInputs = with pkgs; [ bash binutils clang curl curl.dev ];
        configurePhase = ''
          bash -c "./configure --with-libcurl-dir=${pkgs.curl.outPath}/bin --disable-app"
        '';
        buildPhase = ''
          make -j8
        '';
        installPhase = ''
          mkdir -p $out/bin
          cp src/.libs/libacvp.so $out/bin
        '';
        src = ./.;

      };
      
      dev = pkgs.stdenv.mkDerivation {
        name = "libacvp.dev";
 
        configurePhase = "echo 'OK'";
        buildPhase = "echo 'OK'";
        installPhase = ''
          mkdir -p $out/include
          cp include/acvp/acvp.h $out/include
        '';
        src = ./.;
      };
    };

    devShells.${system} = {
      default = (pkgs.buildFHSEnv {
        name = "hdl";
        targetPkgs = pgks: (with pkgs; [
          clang
          curl
          curl.dev
          nushell
          ]);
        runScript = ''
          bash -c "nu"
        '';
      }).env;
     
      actions = (pkgs.mkShell {
        name = "hdl";
        packages = with pkgs; [
          clang
          curl
          curl.dev
        ];
      });
    };
  };
}
