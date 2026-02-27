{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    crane.url = "github:ipetkov/crane";

    fenix = {
      url = "github:nix-community/fenix?rev=6b5325a017a9a9fe7e6252ccac3680cc7181cd63";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      crane,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = (
          import nixpkgs {
            system = system;
            config.allowUnsupportedSystem = true;
            overlays = [ (import rust-overlay) ];
          }
        );

        buildForArchitecture =
          custom_pkgs:
          ((crane.mkLib custom_pkgs).overrideToolchain (p: p.rust-bin.stable.latest.default)).buildPackage {
            name = "arti-facts-${custom_pkgs.stdenv.hostPlatform.config}";
            src = ./.;

            strictDeps = false;
            doCheck = false;

            CARGO_BUILD_TARGET = "${custom_pkgs.stdenv.hostPlatform.rust.rustcTarget}";
            CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";

            TARGET_CC = "${custom_pkgs.stdenv.cc}/bin/${custom_pkgs.stdenv.cc.targetPrefix}cc";

            nativeBuildInputs = [
              custom_pkgs.stdenv.cc
              pkgs.perl
            ];

            buildInputs = [
            ]
            ++ custom_pkgs.lib.optionals custom_pkgs.stdenv.hostPlatform.isWindows [
              custom_pkgs.windows.pthreads
            ]
            ++ custom_pkgs.lib.optionals custom_pkgs.stdenv.hostPlatform.isDarwin [
              custom_pkgs.libiconv
            ];
          };

      in
      {
        packages.linux = buildForArchitecture pkgs.pkgsCross.musl64;
        packages.windows = buildForArchitecture pkgs.pkgsCross.mingwW64;

        defaultPackage = pkgs.symlinkJoin {
          name = "arti-facts";
          paths = [
            (buildForArchitecture pkgs.pkgsCross.musl64)
            (buildForArchitecture pkgs.pkgsCross.mingwW64)
            #(buildForArchitecture pkgs.pkgsCross.aarch64-darwin)
          ];
        };
      }
    );
}
