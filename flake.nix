{
  description = "p2p-observer: observes the Bitcoin P2P network by connecting to its peers";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        rec {
          p2p-observer = pkgs.callPackage ./nix/package.nix { };
          default = p2p-observer;
        }
      );

      # services.p2p-observer (the observer, the metrics and websocket
      # tools, and the archivers)
      nixosModules = rec {
        p2p-observer = import ./nix/module.nix self;
        default = p2p-observer;
      };

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              pkgs.rustc
              pkgs.cargo
              pkgs.clippy
              pkgs.rustfmt
              pkgs.rust-analyzer
              pkgs.cargo-tarpaulin
              pkgs.cargo-mutants

              pkgs.protobuf

              # for integration tests
              pkgs.bitcoind
              pkgs.nats-server
              pkgs.natscli
            ];

            shellHook = ''
              # during the integration tests, don't try to download a bitcoind binary
              # use the nix one instead
              export BITCOIND_SKIP_DOWNLOAD=1
              export BITCOIND_EXE=${pkgs.bitcoind}/bin/bitcoind

              # Use for running integration tests
              export NATS_SERVER_BINARY="${pkgs.nats-server}/bin/nats-server"
            '';
          };
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt-tree);
    };
}
