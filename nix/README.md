# Nix flake

Exposes Prempti as a NixOS / home-manager service. Linux only (x86_64, aarch64).

## Outputs

| Output | What |
|--------|------|
| `packages.<system>.prempti` | Rust workspace: `premptictl`, `claude-interceptor`, `codex-interceptor`, `lib/libcoding_agent.so`, rules and config templates under `share/prempti/` |
| `packages.<system>.falco-bin` | Pre-built Falco 0.44.0 from download.falco.org, patchelf'd for NixOS |
| `nixosModules.prempti` | `services.prempti` → per-user systemd unit for every user on the host |
| `homeManagerModules.prempti` | Same options, unit installed for one user |
| `devShells.default` | cargo/rustc + `FALCO_BIN` pointing at the store Falco |

## NixOS

```nix
{
  inputs.prempti.url = "github:falcosecurity/prempti";   # or path:/path/to/checkout

  outputs = { nixpkgs, prempti, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [
        prempti.nixosModules.prempti
        {
          services.prempti = {
            enable = true;
            mode = "guardrails";        # guardrails | monitor | passthrough
            defaultAction = "allow";    # allow | defer
            rules.no-git-push = ''
              - rule: Deny git push
                desc: Never push from an agent session
                condition: tool.name = "Bash" and tool.input_command startswith "git push"
                output: Falco blocked git push (%tool.input_command)
                priority: CRITICAL
                source: coding_agent
                tags: [coding_agent_deny]
            '';
          };
        }
      ];
    };
  };
}
```

## home-manager

```nix
{
  imports = [ prempti.homeManagerModules.prempti ];
  services.prempti.enable = true;
}
```

## Options

| Option | Default | Notes |
|--------|---------|-------|
| `enable` | `false` | |
| `package` / `falcoPackage` | flake packages | Override to pin or patch |
| `mode` | `guardrails` | Written into `falco.coding_agents_plugin.yaml` |
| `defaultAction` | `allow` | No-rule-match floor (guardrails only) |
| `httpPort` | `2802` | Loopback alert port |
| `pluginSettings` | `{}` | Extra `init_config` keys (e.g. `deny_tags`, `max_request_bytes`); wins over the dedicated options |
| `settings` | `{}` | Extra top-level Falco keys in the generated fragment; override `falco.yaml` scalars (e.g. `log_level`) |
| `mutableConfig` | `false` | See below |
| `defaultRules.enable` | `true` | Ship upstream ruleset |
| `rules.<name>` | `{}` | Inline YAML or path → `rules/user/nix-<name>.yaml` |
| `audit.enable` | `true` | Hash-chained `log/audit.jsonl`; `premptictl audit verify\|tail` |
| `audit.inputMaxBytes` | `16384` | Verbatim `tool_input` per record (sha256 always kept) |
| `monitor.enable` | `false` | LLM monitor (second verdict source) |
| `monitor.endpoint` / `model` | DeepSeek v4.1 flash | OpenAI-compatible chat completions |
| `monitor.apiKeyEnv` | `KEBNETRAILS_API_KEY` | Falls back to `OPENAI_API_KEY` |
| `monitor.environmentFile` | `null` | systemd `EnvironmentFile` with the token; required when enabled |
| `monitor.roeFile` | `null` | Rules of Engagement (path or text) → `config/roe.md` |
| `monitor.timeoutMs` / `onError` | `20000` / `ask` | Hook timeout is derived from `timeoutMs` |
| `monitor.maxTranscriptBytes` / `maxInputBytes` / `workers` | `32768` / `8192` / `4` | |
| `monitor.skipTools` | `[]` | e.g. `[ "Read" "Glob" "Grep" ]` |
| `signoff.enable` | `false` | Hold every `ask` for a hardware-key (FIDO2) sign-off; requires `audit.enable` |
| `signoff.ttlSecs` | `300` | Held calls are denied after this; hook timeout derived from it |
| `signoff.rpId` / `requireUv` | `prempti.local` / `false` | Relying-party id; require PIN/biometric, not just touch |
| `signoff.keysFile` | `null` | `config/signoff_keys.json` to install (public keys only); `null` = `premptictl signoff enroll` owns the file in place |
| `supervisor.logRotateBytes` | `10485760` | |
| `supervisor.logRotateKeep` | `3` | |
| `supervisor.stopTimeoutSecs` | `20` | |

## Changing configuration

Everything is driven by options; edit your NixOS / home-manager config and
`switch`. For anything without a dedicated option use the two freeform
attrsets, rendered into `falco.coding_agents_plugin.yaml` with
`pkgs.formats.yaml`:

```nix
services.prempti = {
  mode = "guardrails";
  pluginSettings = {
    ask_tags = [ "coding_agent_ask" "team_ask" ];   # init_config keys
  };
  settings = {
    log_level = "info";                              # top-level Falco keys
    outputs_queue.capacity = 0;
  };
  rules.team = ./rules/team.yaml;                    # rules/user/nix-team.yaml
};
```

`settings` keys land in the fragment that Falco loads after `falco.yaml`
(`config_files`), so scalars there override the base config. Hand-written
files in `rules/user/` are never touched.

## LLM monitor (Kebnetrails)

```nix
services.prempti = {
  enable = true;
  monitor = {
    enable = true;
    environmentFile = config.sops.secrets."kebnetrails.env".path; # KEBNETRAILS_API_KEY=...
    roeFile = ./roe.md;
    skipTools = [ "Read" "Glob" "Grep" ];
  };
};
```

Every tool call is sent to the model together with the RoE and the tail of
the agent transcript; `ask` / `deny` escalate the Falco verdict, `allow`
leaves it alone. The key is read from the unit's environment once at plugin
start, so it is visible in the Falco process environment for the same user.
`premptictl monitor status` shows the effective settings; `premptictl roe
set <file>` swaps the RoE and restarts the service; `premptictl audit
tail -f` follows the trail.

## Hardware-key sign-off (YubiKey / FIDO2)

```nix
services.prempti = {
  enable = true;
  signoff = {
    enable = true;
    ttlSecs = 300;
    # keysFile = ./signoff_keys.json;  # optional: pin the enrolled keys in Nix
  };
};
# hidraw access to the key for your user:
services.udev.packages = [ pkgs.libfido2 ];
```

Enrol before (or right after) enabling: `premptictl signoff enroll --label
desk` writes `~/.prempti/config/signoff_keys.json` (touch the key; no
running service needed). With `keysFile` unset that file is the source of
truth and rebuilds leave it alone; the service only refuses to start while
sign-off is enabled and nothing is enrolled yet. Set `keysFile` to a copy
if you want the enrolment pinned in your Nix config instead. From then on
every `ask` verdict, whether from a
Falco rule or the LLM monitor, parks the tool call: Claude Code waits, and
`premptictl signoff list` / `signoff watch` show what is pending.
`premptictl signoff approve <seq>` signs the call's audit record hash with
the key and releases it as `allow`; `signoff deny <seq>` needs no key.
Unanswered calls are denied after `ttlSecs`. Every decision is its own
`kind: signoff` record in `audit.jsonl`, carrying the assertion so
`premptictl audit verify` and the audit UI can show who released what.

## How it maps onto upstream's layout

`premptictl` hard-codes `~/.prempti` (hook command, socket paths, in-place
config rewrites), so the module keeps that prefix. `ExecStartPre` runs a
generated script on every start that:

- symlinks `bin/falco`, `bin/premptictl`, both interceptors and
  `share/libcoding_agent.so` to the store;
- writes `config/falco.yaml` from the package;
- writes `config/falco.coding_agents_plugin.yaml` and `config/supervisor.yaml`
  from the module options;
- symlinks `rules/seen.yaml`, `rules/default/coding_agents_rules.yaml`, and
  every `rules.<name>` as `rules/user/nix-<name>.yaml`. Files you drop into
  `rules/user/` by hand are untouched.

`ExecStart` is the upstream supervisor (`premptictl daemon`). It registers the
Claude Code hook in `~/.claude/settings.json` on start and removes it on stop,
exactly as the tarball install does. `premptictl status/health/logs/hook`
work unchanged; `premptictl start/stop/restart` drive the NixOS-managed user
unit through `systemctl --user`.

### `mutableConfig`

With the default `false`, Nix is the source of truth: `premptictl mode
monitor` rewrites the file and restarts the service, and the restart
regenerates the file from `services.prempti.mode` — so the change does not
stick. Change mode/default-action in your Nix config and `nixos-rebuild
switch` instead. Set `mutableConfig = true` to have the module write the two
config files only when absent, after which `premptictl` owns them.

### Caveats

- **Read-only `~/.claude/settings.json`** (e.g. home-manager `home.file`
  symlink) makes hook registration fail and the supervisor refuses to start.
  Keep that file writable.
- **Fail-closed**: while the unit is down and the hook is still registered,
  all Claude Code tool calls are denied. `premptictl hook remove` if you stop
  the service on purpose. On `nixos-rebuild switch` the user unit restarts;
  the window is a few hundred milliseconds.
- **Uninstall**: set `enable = false`, rebuild, then `premptictl hook remove`
  and `rm -rf ~/.prempti` if you want the prefix gone. Do not use
  `premptictl uninstall`; it expects the tarball layout.
- `nix flake check` evaluates the NixOS module and builds the package with
  the unit tests; it does not run the e2e suite (needs a live Falco). The
  dev shell exports `FALCO` pointing at the store Falco, so `nix develop`
  then `make test-e2e` (or `cargo build --release --workspace &&
  cargo test -p prempti-tests --release`) runs the Falco-driven tests.
