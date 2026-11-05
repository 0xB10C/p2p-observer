# NixOS VM test of the p2p-observer module: an observer with a local NATS
# server, the metrics and websocket tools and two archivers, pointed at a
# second machine running Bitcoin Core in regtest as its only bootstrap peer.
#
# Grafana is here to provision the dashboards the metrics tool ships, which is
# the only way to find out that Grafana accepts them: it skips a dashboard
# whose UID or title collides and only warns about it.
{ self, pkgs }:

let
  P2P_PORT = 18444;
  METRICS_PORT = 8282;
  WEBSOCKET_PORT = 47484;
  NATS_PORT = 4222;
  GRAFANA_PORT = 3000;

  ARCHIVE_DIR = "/var/lib/p2p-observer/archive";

  # A random regtest address to mine to, the one the Rust tests use.
  REGTEST_ADDR = "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw";

  bitcoinCli = "${pkgs.bitcoind}/bin/bitcoin-cli -regtest -datadir=/var/lib/bitcoind-regtest";

  # A client that subscribes the way a page does. The status poll is skipped
  # while nobody is subscribed to it -- "an observer is not polled to fill a
  # cache nobody reads" -- so a curl that only upgrades and leaves would never
  # see one.
  wsProbe =
    pkgs.writers.writePython3Bin "p2p-observer-ws-probe"
      {
        libraries = [ pkgs.python3Packages.websockets ];
        flakeIgnore = [ "E501" ];
      }
      ''
        """Subscribes to the websocket, then prints the first status update as JSON."""
        import asyncio
        import json
        import sys

        import websockets


        async def main():
            async with websockets.connect("ws://127.0.0.1:${toString WEBSOCKET_PORT}/") as ws:
                hello = json.loads(await asyncio.wait_for(ws.recv(), 10))
                assert "hello" in hello, hello

                await ws.send(json.dumps({"connection_status": True, "ping_rtt": True}))

                status, event = None, None
                while status is None or event is None:
                    message = json.loads(await asyncio.wait_for(ws.recv(), 30))
                    if "status" in message:
                        status = message["status"]
                    elif "event" in message:
                        event = message["event"]
                    elif "error" in message:
                        sys.exit(f"the server refused the subscription: {message}")

                assert event["network"] == "regtest", event
                print(json.dumps(status))


        asyncio.run(main())
      '';

  dashboards = "${
    self.packages.${pkgs.stdenv.hostPlatform.system}.p2p-observer
  }/share/p2p-observer/dashboards";
in
pkgs.testers.runNixOSTest {
  name = "p2p-observer-module";

  nodes = {
    observer =
      { nodes, ... }:
      {
        imports = [ self.nixosModules.default ];

        # Grafana wants more than the default.
        virtualisation.memorySize = 4096;

        environment.systemPackages = [ wsProbe ];

        services.p2p-observer = {
          enable = true;
          nats.enable = true;
          settings = {
            network = "regtest";
            bootstrap_addrs = [ "${nodes.peer.networking.primaryIPAddress}:${toString P2P_PORT}" ];
            # Ping often, so the ping events and their TCP samples arrive
            # within the test's patience rather than two minutes in.
            ping_interval_secs = 2;
            log_levels.connection = "debug";
          };
          metrics.enable = true;
          websocket = {
            enable = true;
            # Ask the observer what it is connected to every other second,
            # which is the tool's one RPC round trip.
            statusIntervalSecs = 2;
          };
          archivers = {
            # No event filter: everything the observer publishes.
            everything = { };
            # A filtered archiver, which also writes uncompressed and rotates
            # early, to exercise the flags the module builds.
            handshakes = {
              events = [
                "handshakes"
                "ping-rtt"
              ];
              compressionLevel = 3;
              maxFileSize = 65536;
            };
          };
        };

        services.grafana = {
          enable = true;
          settings = {
            server = {
              http_addr = "127.0.0.1";
              http_port = GRAFANA_PORT;
            };
            # World-readable in the store, which is fine for a test VM.
            security.secret_key = "p2p-observer-test";
            # The VM has no network access.
            analytics = {
              reporting_enabled = false;
              check_for_updates = false;
            };
          };
          provision = {
            enable = true;
            dashboards.settings.providers = [
              {
                name = "p2p-observer";
                options = {
                  path = dashboards;
                  # The dashboards sit in sub-directories (`playlist/`).
                  foldersFromFilesStructure = true;
                };
              }
            ];
          };
        };
      };

    peer =
      { ... }:
      {
        environment.systemPackages = [ pkgs.netcat ];
        networking.firewall.allowedTCPPorts = [ P2P_PORT ];
        services.bitcoind.regtest = {
          enable = true;
          port = P2P_PORT;
          extraConfig = ''
            regtest=1
            debug=net
          '';
        };
      };
  };

  testScript = ''
    import json

    start_all()

    peer.wait_for_unit("bitcoind-regtest.service")
    peer.wait_for_open_port(${toString P2P_PORT})

    observer.wait_for_unit("nats.service")
    observer.wait_for_unit("p2p-observer.service")
    observer.wait_for_unit("p2p-observer-metrics.service")
    observer.wait_for_unit("p2p-observer-websocket.service")
    observer.wait_for_unit("p2p-observer-archiver-everything.service")
    observer.wait_for_unit("p2p-observer-archiver-handshakes.service")
    observer.wait_for_open_port(${toString METRICS_PORT})
    observer.wait_for_open_port(${toString WEBSOCKET_PORT})


    def rpc(command):
        """The rpc tool, on PATH because the module installs the package."""
        return json.loads(
            observer.succeed(f"p2p-observer-rpc --network regtest --raw {command}")
        )


    def metric_is_nonzero(metrics, name):
        """A sample of `name` with a value other than zero, labels and all."""
        for line in metrics.splitlines():
            if line.startswith(name) and not line.endswith(" 0"):
                return True
        return False


    with subtest("the observer dials its bootstrap peer and completes a handshake"):
        observer.wait_until_succeeds(
            "p2p-observer-rpc --network regtest --raw connections list"
            + " | grep -q '\"connected\":1'",
            timeout=120,
        )
        connections = rpc("connections list")["connections"]
        assert len(connections) == 1, connections
        assert connections[0]["addr"].endswith(":${toString P2P_PORT}"), connections
        # A handshake the observer completed, rather than a socket it opened.
        assert connections[0]["protocol_version"] >= 70016, connections

    with subtest("nothing the module runs is reachable from the network"):
        # The listen defaults are all loopback, and NATS likewise.
        peer.fail("nc -z -w 2 observer ${toString METRICS_PORT}")
        peer.fail("nc -z -w 2 observer ${toString WEBSOCKET_PORT}")
        peer.fail("nc -z -w 2 observer ${toString NATS_PORT}")

    with subtest("a block mined on the peer reaches the observer's header tree"):
        peer.succeed("${bitcoinCli} generatetoaddress 2 ${REGTEST_ADDR}")
        observer.wait_until_succeeds(
            "p2p-observer-rpc --network regtest --raw headertree tips"
            + " | grep -q '\"height\":2'",
            timeout=60,
        )
        tips = rpc("headertree tips")
        assert [t for t in tips if t["height"] == 2 and t["status"] == "active"], tips

    with subtest("the address book counts the peer it is connected to"):
        assert rpc("addresses info")["connected"] == 1, rpc("addresses info")

    with subtest("the metrics tool counts what the observer published"):
        metrics = observer.succeed("curl -sf 127.0.0.1:${toString METRICS_PORT}/metrics")
        assert "p2pobserver_start_timestamp_seconds 0" not in metrics
        for name in [
            "p2pobserver_events_total",
            "p2pobserver_handshakes_total",
            "p2pobserver_ping_rtt_seconds_count",
            "p2pobserver_block_announcements_total",
        ]:
            assert metric_is_nonzero(metrics, name), f"{name} is missing or zero:\n{metrics}"
        # The mined blocks, as the observer saw them.
        assert metric_is_nonzero(metrics, "p2pobserver_best_height"), metrics

    with subtest("a client gets the events and the status the observer answers with"):
        # The probe upgrades, subscribes, and waits for both an event and a
        # status update. The status is the websocket asking the observer over
        # NATS what it is connected to, which is the one thing in the tool that
        # cannot work without the observer on the other side.
        status = json.loads(observer.succeed("p2p-observer-ws-probe"))
        assert status["network"] == "regtest", status
        assert status["connected"] == 1, status
        assert status["connections"][0]["addr"].endswith(":${toString P2P_PORT}"), status

    with subtest("the archivers write archives the other tools read back"):
        observer.wait_until_succeeds("ls ${ARCHIVE_DIR}/everything.*.bin.zst")
        observer.wait_until_succeeds("ls ${ARCHIVE_DIR}/handshakes.*.bin.zst")
        # Group-readable and no wider, as the module's tmpfiles rule asks.
        observer.succeed("stat -c %a ${ARCHIVE_DIR} | grep -x 750")

        # Stopping drains the subscription and closes the file, which is the
        # difference between a readable archive and a truncated one.
        observer.systemctl(
            "stop p2p-observer-archiver-everything.service"
            + " p2p-observer-archiver-handshakes.service"
        )

        replayed = observer.succeed("p2p-observer-replayer ${ARCHIVE_DIR}/everything.*.bin.zst 2>&1")
        assert "network=regtest" in replayed, replayed
        assert "total:" in replayed, replayed
        for kind in ["Handshake", "PingRtt", "BlockAnnouncement"]:
            assert kind in replayed, f"no {kind} in the unfiltered archive:\n{replayed}"

        summary = observer.succeed("p2p-observer-stats ${ARCHIVE_DIR}/everything.*.bin.zst 2>&1")
        assert "coverage (regtest)" in summary, summary

        # The filtered archiver was given two kinds and must have kept to them.
        filtered = observer.succeed("p2p-observer-replayer ${ARCHIVE_DIR}/handshakes.*.bin.zst 2>&1")
        assert "Handshake" in filtered, filtered
        assert "BlockAnnouncement" not in filtered, filtered

    with subtest("Grafana accepts every dashboard the metrics tool ships"):
        observer.wait_for_unit("grafana.service", timeout=120)
        observer.wait_for_open_port(${toString GRAFANA_PORT}, timeout=120)
        observer.wait_until_succeeds(
            "journalctl -u grafana.service --grep 'finished to provision dashboards'",
            timeout=120,
        )

        # Grafana only warns and skips when two dashboards share a UID or a
        # title, so the log is where that shows up.
        for problem in [
            "the same UID is used more than once",
            "dashboard title is not unique in folder",
            "no database write permissions because of duplicates",
            "failed to save dashboard",
            "failed to load dashboard",
            "failed to walk provisioned dashboards",
            "Failed to provision dashboard",
        ]:
            observer.fail(f"journalctl -u grafana.service --grep '{problem}'")

        # And as a second opinion, every file it was given is a dashboard it has.
        files = int(observer.succeed("find ${dashboards} -type f -name '*.json' | wc -l"))
        provisioned = json.loads(
            observer.succeed(
                "curl --fail --silent --user admin:admin"
                + " 'http://127.0.0.1:${toString GRAFANA_PORT}/api/search?type=dash-db&limit=5000'"
            )
        )
        assert files > 0
        assert len(provisioned) == files, (
            f"provisioned {len(provisioned)} of {files} dashboards: "
            + ", ".join(sorted(d["uid"] for d in provisioned))
        )
  '';
}
