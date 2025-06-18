{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    crane.url = "github:ipetkov/crane";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs
    , crane
    , fenix
    , flake-utils
    , ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        toolchain =
          with fenix.packages.${system};
          combine [
            minimal.rustc
            minimal.cargo
            targets.x86_64-pc-windows-gnu.latest.rust-std
            targets.x86_64-unknown-linux-musl.latest.rust-std
          ];

        craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;

        windows = craneLib.buildPackage {
          name = "arti-facts-windows";
          src = ./.;

          strictDeps = false;
          doCheck = false;

          CARGO_BUILD_TARGET = "x86_64-pc-windows-gnu";
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";

          # fixes issues related to libring
          TARGET_CC = "${pkgs.pkgsCross.mingwW64.stdenv.cc}/bin/${pkgs.pkgsCross.mingwW64.stdenv.cc.targetPrefix}cc";

          depsBuildBuild = with pkgs; [
            pkgsCross.mingwW64.stdenv.cc
            pkgsCross.mingwW64.windows.pthreads
            perl
          ];
        };

        linux = craneLib.buildPackage {
          name = "arti-facts-linux";
          src = ./.;

          strictDeps = false;
          doCheck = false;

          CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";

          TARGET_CC = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/${pkgs.pkgsCross.musl64.stdenv.cc.targetPrefix}cc";

          nativeBuildInputs = with pkgs; [
            clang
            perl
            libclang
          ];
        };
      in
      {
        packages.linux = linux;
        packages.windows = windows;

        defaultPackage = pkgs.symlinkJoin {
          name = "arti-facts";
          paths = [ linux windows ];
        };
      }
    );
}
