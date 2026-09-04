# Hello Erlang

A demonstration Erlang project showcasing multiple third-party dependencies using `rebar3`.

## Features
- **JSON Handling**: Uses `jiffy` and `jsx`.
- **Logging**: Implements `lager`.
- **HTTP Client**: Includes `hackney`, used by `hello_world_http` to fetch a greeting.
- **Testing**: Uses `EUnit`, with `meck` to mock `hackney` and a local `cowboy` server for
  one end-to-end test.
- **Dev tooling**: `recon` and `hex_core` in the `dev` profile.

## Dependency scopes

rebar3 scopes dependencies with profiles. The default profile's `deps` ship in every build,
including releases. Profile deps exist only when that profile is active: `rebar3 as dev ...`
for `dev`, and `test`, which rebar3 activates itself for `rebar3 eunit`.

| Scope | Packages | Available when |
|---|---|---|
| default (prod) | `jiffy`, `jsx`, `lager`, `hackney` | always, including releases |
| dev profile | `recon`, `hex_core` | `rebar3 as dev <task>` |
| test profile | `meck`, `cowboy` | `rebar3 eunit`, `rebar3 as test <task>` |

rebar3 records only the default profile in `rebar.lock`; profile deps are pinned by exact
version in `rebar.config` instead, so a scanner that reads only the lockfile will not see them.

## Deliberately vulnerable dependencies

This project exists to demonstrate the dependably vulnerability scanner, so one package in
each scope is pinned to a release with a published advisory. Nothing in the project calls
the affected code paths. Do not "fix" these pins without also updating this table.

| Scope | Package | Advisory | Fixed in |
|---|---|---|---|
| default (prod) | `hackney 1.18.0` | several 2026 advisories, e.g. CVE-2026-47071 (SOCKS5 TLS upgrade ignores the caller timeout, HIGH) | 4.0.1 |
| dev profile | `hex_core 0.11.0` | CVE-2026-21619 / GHSA-hx9w-f2w9-9g96, unsafe deserialization of Erlang terms | 0.12.1 |
| test profile | `cowboy 2.12.0` | CVE-2026-8466 / GHSA-jfc2-q6qh-g5x8, unbounded buffer accumulation in multipart header parsing (HIGH) | 2.15.0 |

`cowlib 2.13.0`, pulled in by that cowboy, carries several advisories of its own.

## SBOM, reachability, and upload to dependably

The CI `sbom` stage runs `rebar3 sbom` for the default, `dev`, and `test` profiles (the
`rebar3_sbom` plugin), and `scripts/sbom_tool.py` unions the three XML documents into one
CycloneDX 1.6 JSON SBOM with profile-only packages marked `scope: excluded`. It then enriches
the SBOM with the advisories the dependably registry already knows for each package and runs
[sbom-reach](https://gitlab.northwardlabs.ca/moonlitlabs/sbom-reachability) over it to produce
SARIF. The `publish` stage PUTs the SBOM and the SARIF to dependably's projects plane as
project `hello-erlang`, version = tag or branch slug.

Two limits to know about:

- sbom-reach has no Hex analyzer, so every SARIF result carries reachability `unknown`.
  What the SARIF adds over the SBOM is the advisory list and the dev/test scope per finding.
- The upload needs `DEPENDABLY_SBOM_TOKEN`, a dependably API token with only the
  `sbom:upload` capability, set as a masked and protected CI/CD variable. The read-only
  registry key cannot upload.

To reproduce locally (needs `REGISTRY_URL` and `REGISTRY_KEY` in the environment):

```bash
rebar3 sbom -f -o bom-default.xml
rebar3 as dev sbom -f -o bom-dev.xml
rebar3 as test sbom -f -o bom-test.xml
python3 scripts/sbom_tool.py rebar3 bom-default.xml bom-dev.xml bom-test.xml bom.cdx.json
python3 scripts/sbom_tool.py enrich bom.cdx.json bom.vulns.cdx.json
sbom-reach analyze --sbom bom.vulns.cdx.json --src . --fail-on none -o results.sarif
```

## Prerequisites

You will need the Erlang runtime and `rebar3` (the Erlang build tool) installed on your machine.

### macOS
```bash
brew install erlang rebar3
```

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install erlang rebar3
```

### Windows
The easiest way is via [Chocolatey](https://chocolatey.org/):
```powershell
choco install erlang rebar3
```

## Getting Started

### 1. Configure the private registry
All Hex packages are pulled from the private dependably registry (`https://dependably.northwardlabs.ca/hex`),
which `rebar.config` registers under the repo name `dependably`. The registry requires a token,
which is kept out of the repository. Put yours in rebar3's per-user auth file:

```bash
mkdir -p ~/.config/rebar3
cat > ~/.config/rebar3/hex.config <<'EOF'
#{<<"dependably">> => #{repo_key => <<"YOUR_TOKEN">>, api_key => <<"YOUR_TOKEN">>}}.
EOF
chmod 600 ~/.config/rebar3/hex.config
```

CI writes this file itself from the shared `REGISTRY_URL` / `REGISTRY_KEY` variables.

### 2. Install Dependencies
Navigate to the project root and run:
```bash
rebar3 update
rebar3 get-deps
```

### 3. Compile the Project
```bash
rebar3 compile
```

### 4. Run Tests
Verify the project is working correctly using the EUnit test suite (this activates the
`test` profile and fetches `meck` and `cowboy`):
```bash
rebar3 eunit
```

### 5. Dev Profile
Build with the `dev` profile to get `recon` and `hex_core` on the code path:
```bash
rebar3 as dev compile
rebar3 as dev shell
```

### 6. Run the Demo
You can start an interactive Erlang shell with the project loaded and run the demo module:
```bash
rebar3 shell
```

Once inside the Erlang shell (`erl`), run:
```erlang
hello_world_demo:run().
```

## Project Structure
- `src/`: Source code (`.erl` files)
- `test/`: Test suites (`.erl` files using EUnit)
- `rebar.config`: Project configuration, dependencies, profiles, and the `rebar3_sbom` plugin
- `scripts/sbom_tool.py`: SBOM merge/enrich helper used by CI
```

