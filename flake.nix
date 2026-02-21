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
    {
      nixpkgs,
      crane,
      fenix,
      flake-utils,
      ...
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

        buildForArchitecture =
          custom_pkgs:
          craneLib.buildPackage {
            name = "arti-facts-${custom_pkgs.stdenv.hostPlatform.config}";
            src = ./.;

            strictDeps = false;
            doCheck = false;

            CARGO_BUILD_TARGET = "${custom_pkgs.stdenv.hostPlatform.rust.rustcTarget}";
            CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
            # fixes issues related to libring
            TARGET_CC = "${custom_pkgs.stdenv.cc}/bin/${custom_pkgs.stdenv.cc.targetPrefix}cc";

            depsBuildBuild =
              [
                custom_pkgs.stdenv.cc
                pkgs.perl
              ]
              ++ pkgs.lib.optionals custom_pkgs.stdenv.buildPlatform.isWindows [
                custom_pkgs.windows.pthreads
              ]
              ++ pkgs.lib.optionals custom_pkgs.stdenv.buildPlatform.isDarwin [
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
