<p align="center"><img src="assets/logo.png" alt="ToolGlass" width="140"></p>

# ToolGlass

**Show what your agent actually sees.** A local, offline-first Rust audit of the MCP tool surface your AI
coding assistant (**Claude Code, Cursor, Codex, VS Code, Cline, goose**) exposes to the model: descriptions,
env keys, approval states, poisoning signals, and exfiltration paths, *before* it runs them.

`local-first · offline · detection-only · cross-client · single binary`

**English** · [中文](README.zh-CN.md)

[![Rust](https://img.shields.io/badge/Rust-2024-b7410e?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-launch--ready-brightgreen)](#status)
[![MCP](https://img.shields.io/badge/MCP-audit-7a1fa2)](#)

<p align="center"><img src="assets/hero.png" alt="ToolGlass hero" width="800"></p>

---

ToolGlass is **not another scanner**. It is an *Agent Visible Surface* report: transparent, local,
diffable, and packaged as a single Rust binary. Nothing is sent anywhere; no MCP server is executed
unless you explicitly opt in with live introspection.

## Status

**Launch-ready Rust crate.** ToolGlass currently ships config scanning across 6 clients, live
`tools/list` introspection for stdio MCP servers, tool-poisoning detections (TG-101/102/103), a
cross-server exfiltration flow graph, a safe demo, and terminal/Markdown/HTML/SARIF/JSON reports.
The test suite covers the Rust core and the GitHub Action emits SARIF for code scanning.

## Stack

- Rust crate: `tool-glass`
- Binary: `tool-glass`
- Reports: `terminal`, `md`, `html`, `sarif`, `json`
- Clients: Claude Code, Cursor, Codex, VS Code, Cline, goose
- Distribution today: prebuilt release binaries or source builds

## Why

MCP tools are *model-controlled*: the agent can read tool descriptions and `instructions` that you
never see in the client UI. ToolGlass prints exactly what is exposed, locally, so you can review it
like a diff before trusting a third-party MCP server.

Unlike hosted scanners (e.g. Snyk Agent Scan / Invariant MCP-Scan), ToolGlass is **open source,
fully local, and offline**: your tool descriptions never leave your machine. It prioritizes the
*explanation* (an Agent Visible Surface report + an exfiltration path map) over hosted policy
enforcement. Snyk is a broad commercial AppSec platform; ToolGlass is a small local lens focused on
what AI agents can see and how tool descriptions can steer them.

## Install

Download the prebuilt binary for your platform from
[Releases](https://github.com/Loping151/ToolGlass/releases), extract the archive, and put
`tool-glass` or `tool-glass.exe` somewhere on your `PATH`.

Or install from source with Cargo:

```bash
cargo install --path .
tool-glass --version
```

You can also build a release binary locally:

```bash
cargo build --release
./target/release/tool-glass --version
```

The local release build produces `target/release/tool-glass` on Unix-like systems and
`target/release/tool-glass.exe` on Windows.

## Quick start

Scan your local configs:

```bash
cargo run --quiet -- scan
cargo run --quiet -- scan --report json
```

Scan a specific project or config root:

```bash
cargo run --quiet -- scan --cwd .
cargo run --quiet -- scan --home /path/to/home --cwd /path/to/project
```

Write reports:

```bash
cargo run --quiet -- scan --report md -o tool_glass.md
cargo run --quiet -- scan --report html -o tool_glass.html
cargo run --quiet -- scan --report sarif -o tool_glass.sarif
```

Use the compiled binary after `cargo build --release`:

```bash
./target/release/tool-glass scan --cwd . --report sarif -o tool_glass.sarif
```

Live introspection is explicit:

```bash
cargo run --quiet -- scan --cwd . --live --yes
```

## Demo

See the attack with zero setup:

```bash
cargo run --quiet -- demo
```

Or with the release binary:

```bash
./target/release/tool-glass demo
```

ToolGlass introspects two bundled fake MCP servers. A weather tool that looks harmless is revealed
to hide a stealth instruction telling the model to read a private file and send it to a chat tool,
and ToolGlass maps the `get_weather -> send_message` exfiltration path. Nothing is executed: the
path is *revealed*, not *run*.

## CI / GitHub Action

Audit MCP configs on every PR and surface findings in the **Security** tab.

**Reusable action** (for public repositories):

```yaml
# .github/workflows/tool_glass.yml
name: tool_glass
on: [pull_request, push]
permissions:
  contents: read
  security-events: write
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Loping151/ToolGlass@main
        with:
          path: .
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: tool_glass.sarif
          category: tool_glass
```

The composite action installs the stable Rust toolchain, builds ToolGlass with
`cargo build --release`, runs:

```bash
target/release/tool-glass scan --cwd <path> --report sarif -o <sarif-path>
```

and exposes the SARIF path as the `sarif` output. This repository also ships its own workflow at
`.github/workflows/tool_glass.yml` that runs `cargo test`, builds the release binary, scans the repo,
and uploads SARIF. Findings annotate; they do not block by default.

## Roadmap

- [x] Config-only scan: Claude Code, Cursor, Codex, VS Code, Cline, goose
- [x] Live `tools/list` introspection (stdio, restricted env, never calls tools)
- [x] Tool-poisoning rules (TG-101/102/103) + cross-server exfil flow graph
- [x] Reports: terminal, Markdown, HTML, SARIF, JSON
- [x] GitHub Action with SARIF upload workflow
- [ ] Baseline diff (fail CI only on newly-introduced risks)
- [ ] More clients (Windsurf, Zed)
- [ ] crates.io package

## Disclaimer

ToolGlass audits **your own local configs only**. By default it never executes an MCP server, never
reads secret **values** (only env key *names*), and never touches the network. Live introspection is
explicit and limited to listing tools from discovered stdio MCP servers.
