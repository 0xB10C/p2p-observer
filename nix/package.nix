{
  lib,
  rustPlatform,
  protobuf,
  bitcoind,
  nats-server,
}:

let
  # The workspace has no shared version; the observer is what the package is
  # named after, so its version is the package's.
  observerToml = lib.importTOML ../observer/Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = "p2p-observer";
  inherit (observerToml.package) version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      # included by a unit test in observer/src/settings.rs
      ../config-example.yaml
      ../common
      ../observer
      ../testsupport
      ../tools
    ];
  };

  # Hash of the vendored dependencies; update it whenever Cargo.lock changes
  # (set it to lib.fakeHash, build, and copy the hash from the error).
  # `cargoLock.lockFile` would avoid that, but it can't vendor two crates with
  # the same name and version from different sources, which Cargo.lock has:
  # bitcoin-io 0.2.0 and bitcoin_hashes 0.16.0 come both from crates.io and
  # from the rust-bitcoin git revision that bip324 pins. That pair is also why
  # the flake needs a nixpkgs with the fixed vendor layout -- on nixos-25.11
  # the fetcher collides on the directory name and the build never starts.
  cargoHash = "sha256-G7gHTc5SrJeOcTbT3aQaPVyO38EN5qTbElC1wFTg8CU=";

  # protoc for prost-build in common/build.rs
  nativeBuildInputs = [ protobuf ];

  # The checkPhase runs the whole test suite, which needs both of these
  # binaries: the tests that talk to a real bitcoind panic without one
  # (`bitcoind::exe_path().unwrap()`), and the ones that need NATS skip
  # themselves when NATS_SERVER_BINARY is unset, which would quietly cost most
  # of the integration coverage.
  nativeCheckInputs = [
    bitcoind
    nats-server
  ];

  env = {
    # corepc-node, a dev-dependency, downloads a bitcoind in its build script
    # unless told not to. The one above is the one to use.
    BITCOIND_SKIP_DOWNLOAD = "1";
    BITCOIND_EXE = lib.getExe' bitcoind "bitcoind";
    NATS_SERVER_BINARY = lib.getExe' nats-server "nats-server";
  };

  # The Grafana dashboards of the metrics tool and the browser pages of the
  # websocket tool. The pages expect a websockets.json next to them, which
  # whoever serves them provides.
  postInstall = ''
    mkdir -p $out/share/p2p-observer
    cp -r tools/metrics/dashboards $out/share/p2p-observer/dashboards

    mkdir -p $out/share/p2p-observer-websocket
    cp -r tools/websocket/www $out/share/p2p-observer-websocket/www
    rm -f $out/share/p2p-observer-websocket/www/websockets.example.json
    rm -f $out/share/p2p-observer-websocket/www/.gitignore
  '';

  meta = {
    description = "Observes the Bitcoin P2P network by connecting to its peers";
    homepage = "https://github.com/0xb10c/p2p-observer";
    license = lib.licenses.mit;
    mainProgram = "p2p-observer";
    platforms = lib.platforms.unix;
  };
}
