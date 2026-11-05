# NixOS module for p2p-observer and its tools.
#
#   services.p2p-observer = {
#     enable = true;
#     nats.enable = true;
#     settings = {
#       network = "signet";
#       bootstrap_addrs = [ "1.2.3.4:38333" ];
#     };
#     metrics.enable = true;
#     websocket.enable = true;
#     archivers.signet = { };
#   };
#
# p2p-observer-rpc, p2p-observer-logger, p2p-observer-csv, p2p-observer-stats
# and p2p-observer-replayer are installed but not run as services: the first
# two are things an operator points at a running observer, the last three read
# what the archiver wrote.
#
# The observer publishes to NATS; set `services.p2p-observer.nats.enable` for a
# local server, or point `settings.nats_url` at one that exists.
self:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.p2p-observer;
  settingsFormat = pkgs.formats.yaml { };
  configFile = settingsFormat.generate "p2p-observer.yaml" cfg.settings;

  # The observer and the tools reach NATS the same way. Only the observer
  # takes it from the config file; every tool takes it on the command line.
  natsArgs = [
    "--nats-url"
    cfg.settings.nats_url
  ];

  # `--network` of a tool: the observer's network unless the option says
  # otherwise. `null` means every network, which only differs from the default
  # when another observer publishes to the same NATS server.
  networkArgs =
    network:
    lib.optionals (network != null) [
      "--network"
      network
    ];

  # Everything the observer and the tools have in common. The observer makes
  # outbound connections and listens on nothing, so unlike a node there is no
  # capability to keep here.
  commonServiceConfig = {
    User = cfg.user;
    Group = cfg.group;
    Restart = "always";
    RestartSec = 10;
    # Every binary stops on SIGTERM as well as SIGINT and writes out what it
    # has -- the address book, unsaved headers, the open archive file -- so the
    # default KillSignal is the right one. TimeoutStopSec is generous because
    # that write is the difference between a readable archive and a truncated
    # one.
    TimeoutStopSec = 30;

    NoNewPrivileges = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";
    RestrictAddressFamilies = [
      "AF_INET"
      "AF_INET6"
      "AF_UNIX"
    ];
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = [
      "@system-service"
      "~@privileged"
    ];
    CapabilityBoundingSet = "";
    UMask = "0027";
  };

  natsUnits = lib.optional cfg.nats.enable "nats.service";
  unitDeps = {
    after = [ "network-online.target" ] ++ natsUnits;
    wants = [ "network-online.target" ] ++ natsUnits;
    wantedBy = [ "multi-user.target" ];
  };

  # The archiver's event filters, spelled as its flags are. Naming them after
  # the flags keeps the mapping below a single interpolation.
  eventKinds = [
    "ping-rtt"
    "block-announcements"
    "address-announcements"
    "connection-results"
    "handshakes"
    "compact-block-probes"
    "fee-filters"
    "send-cmpcts"
  ];

  archiverOpts =
    { name, ... }:
    {
      options = {
        baseName = lib.mkOption {
          type = lib.types.strMatching "[A-Za-z0-9_.-]+";
          default = name;
          defaultText = lib.literalExpression "<name>";
          description = "File name prefix of the archives (`--base-name`). Unique per archiver, as all of them write to `archiveDir`.";
        };
        events = lib.mkOption {
          type = lib.types.listOf (lib.types.enum eventKinds);
          default = [ ];
          example = [
            "address-announcements"
            "connection-results"
          ];
          description = ''
            Which events to archive, each passed as the flag of the same name.
            The empty default passes no filter at all, which is how the
            archiver is told to write everything -- including event kinds added
            after this build, whose bytes it keeps verbatim.
          '';
        };
        maxFileSize = lib.mkOption {
          type = lib.types.nullOr lib.types.ints.positive;
          default = null;
          example = 104857600;
          description = "Rotate archive files at this many bytes on disk (`--max-file-size`). `null` keeps the archiver's default of 1 GiB.";
        };
        compressionLevel = lib.mkOption {
          type = lib.types.nullOr (lib.types.ints.between 0 22);
          default = null;
          example = 3;
          description = ''
            zstd compression level (`--compression-level`); 0 writes plain
            `.bin` files. `null` keeps the archiver's default of 18. Use 3 when
            the archiver has to keep up with a busy stream on a small machine.
          '';
        };
        extraArgs = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          description = "Extra arguments for p2p-observer-archiver.";
        };
      };
    };
in
{
  options.services.p2p-observer = {
    enable = lib.mkEnableOption "p2p-observer, which observes the Bitcoin P2P network by connecting to its peers";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.p2p-observer;
      defaultText = lib.literalExpression "p2p-observer.packages.\${system}.p2p-observer";
      description = "The p2p-observer package. Provides the observer and all tools.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "p2p-observer";
      description = "User the observer and the tools run as.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "p2p-observer";
      description = "Group the observer and the tools run as. The state directory and the archives are readable by this group.";
    };

    nats.enable = lib.mkEnableOption "a NATS server listening on 127.0.0.1:4222 (`services.nats`)";

    settings = lib.mkOption {
      description = ''
        Observer configuration, written to YAML and passed to the observer as
        its config file. See
        <https://github.com/0xb10c/p2p-observer/blob/master/config-example.yaml>
        for every key; unknown keys are ignored rather than rejected, so check
        the spelling against that file.

        This lands in the Nix store, which is world-readable. Credentials in
        `nats_url` are readable by every user on the host.
      '';
      example = lib.literalExpression ''
        {
          network = "signet";
          bootstrap_addrs = [ "1.2.3.4:38333" ];
          ping_interval_secs = 60;
          networks.ipv6.enabled = true;
          log_levels.connection = "debug";
        }
      '';
      type = lib.types.submodule {
        freeformType = settingsFormat.type;
        options = {
          network = lib.mkOption {
            type = lib.types.enum [
              "mainnet"
              "bitcoin"
              "signet"
              "testnet3"
              "testnet"
              "testnet4"
              "regtest"
            ];
            default = "mainnet";
            description = "The Bitcoin network, as the observer spells it. Also the network token of every NATS subject, and the name of the subdirectory under `datadir` holding this network's state.";
          };
          datadir = lib.mkOption {
            type = lib.types.path;
            default = "/var/lib/p2p-observer";
            description = "Where the headers, the address book and the ban list are kept, under a subdirectory per network. Created with mode 0750, owned by `user` and `group`.";
          };
          nats_url = lib.mkOption {
            type = lib.types.str;
            default = "nats://127.0.0.1:4222";
            description = "NATS server the observer publishes to and answers RPCs on. The tools are pointed at the same server.";
          };
          bootstrap_addrs = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            example = [ "1.2.3.4:8333" ];
            description = ''
              Peers to start from, as `ip:port`. The observer syncs its headers
              from these and asks them for addresses, so an observer with an
              empty list and no `addresses.bin` in its `datadir` has nowhere to
              begin. One or two semi-trusted nodes are enough.
            '';
          };
        };
      };
    };

    maxOpenFiles = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.positive;
      default = null;
      example = 65536;
      description = ''
        `LimitNOFILE` of the observer. `null` leaves systemd's default, which
        is what the observer wants: nothing caps its established connections,
        so at startup it raises its own soft limit to the hard one and reports
        the headroom. Set this only to move that hard limit, and never below
        `settings.addrman.max_dialing` plus 64, which the observer refuses to
        start under.
      '';
    };

    archiveDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/p2p-observer/archive";
      description = "Directory all archivers write to. Created with mode 0750, owned by `user` and `group`.";
    };

    metrics = {
      enable = lib.mkEnableOption "p2p-observer-metrics, which turns the event stream into Prometheus metrics";
      listen = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1:8282";
        description = "Address the metrics HTTP server listens on; the metrics are at `/metrics`.";
      };
      network = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = cfg.settings.network;
        defaultText = lib.literalExpression "config.services.p2p-observer.settings.network";
        description = "Only count events of this network. `null` counts every network on the NATS server, which matters when another observer publishes to it.";
      };
      extraArgs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "Extra arguments for p2p-observer-metrics.";
      };
      dashboards = lib.mkOption {
        type = lib.types.path;
        readOnly = true;
        default = "${cfg.package}/share/p2p-observer/dashboards";
        defaultText = lib.literalExpression ''"''${package}/share/p2p-observer/dashboards"'';
        description = "The Grafana dashboards of the metrics tool, one JSON file each, for `services.grafana.provision`.";
      };
    };

    websocket = {
      enable = lib.mkEnableOption "p2p-observer-websocket, which relays the events and the observer's status to browsers";
      listen = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1:47484";
        description = "Address the websocket server listens on.";
      };
      network = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = cfg.settings.network;
        defaultText = lib.literalExpression "config.services.p2p-observer.settings.network";
        description = "Only relay events of this network. `null` relays every network on the NATS server.";
      };
      asmap = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        example = "/var/lib/p2p-observer/latest_asmap.dat";
        description = "Bitcoin Core asmap file for IP to ASN lookups (`--asmap`), e.g. from <https://github.com/bitcoin-core/asmap-data>. Without it the relayed events carry no ASN.";
      };
      statusIntervalSecs = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = 60;
        description = "Seconds between the status updates the tool asks the observer for over RPC and forwards to subscribed clients. 0 turns them off.";
      };
      extraArgs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "Extra arguments for p2p-observer-websocket.";
      };
      www = lib.mkOption {
        type = lib.types.path;
        readOnly = true;
        default = "${cfg.package}/share/p2p-observer-websocket/www";
        defaultText = lib.literalExpression ''"''${package}/share/p2p-observer-websocket/www"'';
        description = "The browser pages for the websocket, to be served next to a `websockets.json` by a webserver.";
      };
    };

    archivers = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule archiverOpts);
      default = { };
      example = lib.literalExpression ''
        {
          everything = { };
          addresses.events = [ "address-announcements" "connection-results" ];
        }
      '';
      description = "p2p-observer-archiver instances, each running as `p2p-observer-archiver-<name>.service` and writing to `archiveDir`.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          let
            names = map (a: a.baseName) (lib.attrValues cfg.archivers);
          in
          lib.length names == lib.length (lib.unique names);
        message = "services.p2p-observer.archivers: baseName must be unique, as all archivers share archiveDir.";
      }
    ];

    users.users = lib.mkIf (cfg.user == "p2p-observer") {
      p2p-observer = {
        isSystemUser = true;
        group = cfg.group;
      };
    };
    users.groups = lib.mkIf (cfg.group == "p2p-observer") { p2p-observer = { }; };

    environment.systemPackages = [ cfg.package ];

    services.nats = lib.mkIf cfg.nats.enable {
      enable = true;
      settings = {
        listen = lib.mkDefault "127.0.0.1:4222";
        http = lib.mkDefault "127.0.0.1:8222";
      };
    };

    systemd.tmpfiles.settings."10-p2p-observer" = {
      ${toString cfg.settings.datadir}.d = {
        user = cfg.user;
        group = cfg.group;
        mode = "0750";
      };
    }
    // lib.optionalAttrs (cfg.archivers != { }) {
      ${toString cfg.archiveDir}.d = {
        user = cfg.user;
        group = cfg.group;
        mode = "0750";
      };
    };

    systemd.services = {
      p2p-observer = unitDeps // {
        description = "p2p-observer";
        restartTriggers = [ configFile ];
        serviceConfig =
          commonServiceConfig
          // {
            ExecStart = lib.escapeShellArgs [
              (lib.getExe cfg.package)
              "${configFile}"
            ];
            ReadWritePaths = [ cfg.settings.datadir ];
          }
          // lib.optionalAttrs (cfg.maxOpenFiles != null) { LimitNOFILE = cfg.maxOpenFiles; };
      };

      p2p-observer-metrics = lib.mkIf cfg.metrics.enable (
        unitDeps
        // {
          description = "p2p-observer metrics";
          serviceConfig = commonServiceConfig // {
            ExecStart = lib.escapeShellArgs (
              [
                (lib.getExe' cfg.package "p2p-observer-metrics")
                "--listen"
                cfg.metrics.listen
              ]
              ++ networkArgs cfg.metrics.network
              ++ natsArgs
              ++ cfg.metrics.extraArgs
            );
          };
        }
      );

      p2p-observer-websocket = lib.mkIf cfg.websocket.enable (
        unitDeps
        // {
          description = "p2p-observer websocket";
          serviceConfig = commonServiceConfig // {
            ExecStart = lib.escapeShellArgs (
              [
                (lib.getExe' cfg.package "p2p-observer-websocket")
                "--listen"
                cfg.websocket.listen
                "--status-interval-secs"
                (toString cfg.websocket.statusIntervalSecs)
              ]
              ++ networkArgs cfg.websocket.network
              ++ lib.optionals (cfg.websocket.asmap != null) [
                "--asmap"
                (toString cfg.websocket.asmap)
              ]
              ++ natsArgs
              ++ cfg.websocket.extraArgs
            );
          };
        }
      );
    }
    // lib.mapAttrs' (
      name: a:
      lib.nameValuePair "p2p-observer-archiver-${name}" (
        unitDeps
        // {
          description = "p2p-observer archiver ${name}";
          serviceConfig = commonServiceConfig // {
            ReadWritePaths = [ cfg.archiveDir ];
            ExecStart = lib.escapeShellArgs (
              [
                (lib.getExe' cfg.package "p2p-observer-archiver")
                "--network"
                cfg.settings.network
                "--output-dir"
                (toString cfg.archiveDir)
                "--base-name"
                a.baseName
              ]
              ++ map (e: "--${e}") a.events
              ++ lib.optionals (a.maxFileSize != null) [
                "--max-file-size"
                (toString a.maxFileSize)
              ]
              ++ lib.optionals (a.compressionLevel != null) [
                "--compression-level"
                (toString a.compressionLevel)
              ]
              ++ natsArgs
              ++ a.extraArgs
            );
          };
        }
      )
    ) cfg.archivers;
  };
}
