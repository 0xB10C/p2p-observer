{
  description = "p2p-observer dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      devShells = forAllSystems (system:
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
        });
    };
}
