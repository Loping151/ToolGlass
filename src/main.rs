mod adapters;
mod analysis;
mod demo;
mod ir;
mod mcp;
mod report;
mod rules;
mod scan;

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "tool-glass",
    version,
    about = "ToolGlass — show what your agent actually sees"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan local MCP/agent configs and print the Agent Visible Surface + findings.
    Scan {
        #[arg(long, help = "Override HOME (config discovery root).")]
        home: Option<PathBuf>,
        #[arg(long, help = "Override project directory.")]
        cwd: Option<PathBuf>,
        #[arg(
            long,
            help = "Comma-separated client filter: claude_code,cursor,codex,vscode,cline,goose"
        )]
        clients: Option<String>,
        #[arg(
            long,
            default_value = "terminal",
            help = "terminal | md | html | json | sarif"
        )]
        report: String,
        #[arg(short = 'o', long, help = "Write report to this path.")]
        output: Option<PathBuf>,
        #[arg(long, help = "Live-introspect discovered stdio servers.")]
        live: bool,
        #[arg(long, help = "Non-interactive confirmation for --live.")]
        yes: bool,
        #[arg(
            long,
            help = "Allow --live to execute stdio servers flagged by TG-003."
        )]
        run_dangerous: bool,
    },
    /// Run the safe 'poisoned MCP' demo.
    Demo {
        #[arg(
            long,
            default_value = "terminal",
            help = "terminal | md | html | json | sarif"
        )]
        report: String,
        #[arg(short = 'o', long, help = "Write report to this path.")]
        output: Option<PathBuf>,
    },
    #[command(name = "_demo-server", hide = true)]
    DemoServer { kind: String },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan {
            home,
            cwd,
            clients,
            report,
            output,
            live,
            yes,
            run_dangerous,
        } => {
            let client_filter = parse_client_filter(clients);
            let result = scan::run_scan(home.as_deref(), cwd.as_deref(), client_filter.as_deref())?;

            if live {
                let launches = scan::live_launches(&result);
                print_live_launches(&launches);
                enforce_live_confirmation(&launches, yes, run_dangerous)?;

                let (tools, findings, edges, notes) = scan::run_live(&result);
                for n in &notes {
                    eprintln!("{n}");
                }
                let text = if tools.is_empty() {
                    eprintln!("No MCP servers could be live-introspected; showing config report.");
                    render_scan_report(&report, &result)?
                } else {
                    render_live_report(&report, &tools, &findings, &edges)?
                };
                emit(&text, output.as_deref())?;
                return Ok(());
            }

            let text = render_scan_report(&report, &result)?;
            emit(&text, output.as_deref())?;
        }
        Commands::Demo { report, output } => {
            let text = demo::run_report(&report)?;
            emit(&text, output.as_deref())?;
        }
        Commands::DemoServer { kind } => demo::server(&kind)?,
    }
    Ok(())
}

fn print_live_launches(launches: &[scan::LiveLaunch]) {
    if launches.is_empty() {
        return;
    }

    eprintln!("--live will start these stdio MCP servers:");
    for launch in launches {
        let env = if launch.env_keys.is_empty() {
            "-".to_string()
        } else {
            launch.env_keys.join(",")
        };
        let args = if launch.args.is_empty() {
            String::new()
        } else {
            format!(" {}", launch.args.join(" "))
        };
        if let Some(matched) = &launch.suspicious_match {
            eprintln!(
                "\x1b[31mDANGEROUS TG-003 {}.{}: {}{} [env: {}] matched {:?}\x1b[0m",
                launch.client, launch.server, launch.command, args, env, matched
            );
        } else {
            eprintln!(
                "  {}.{}: {}{} [env: {}]",
                launch.client, launch.server, launch.command, args, env
            );
        }
    }
}

fn enforce_live_confirmation(
    launches: &[scan::LiveLaunch],
    yes: bool,
    run_dangerous: bool,
) -> anyhow::Result<()> {
    if launches.is_empty() {
        return Ok(());
    }

    let dangerous: Vec<_> = launches
        .iter()
        .filter(|launch| launch.suspicious_match.is_some())
        .collect();

    if !dangerous.is_empty() {
        let action = if run_dangerous {
            "Warning: --live may execute"
        } else {
            "Refusing --live:"
        };
        eprintln!(
            "\x1b[31m{action} {} stdio server(s) matching TG-003 suspicious_command.\x1b[0m",
            dangerous.len()
        );
        for launch in &dangerous {
            eprintln!("  dangerous server: {}.{}", launch.client, launch.server);
        }
        if !run_dangerous {
            anyhow::bail!("use --run-dangerous to force live introspection of TG-003 servers");
        }
        eprintln!("\x1b[31m--run-dangerous set; TG-003 servers may now be executed.\x1b[0m");
    }

    if yes {
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        anyhow::bail!("--live requires --yes when stdin is not interactive");
    }

    eprint!("Proceed? [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    match answer.trim() {
        "y" | "Y" | "yes" | "YES" | "Yes" => Ok(()),
        _ => anyhow::bail!("aborted by user"),
    }
}

fn parse_client_filter(clients: Option<String>) -> Option<Vec<String>> {
    let clients = clients?;
    let requested: Vec<String> = clients
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();
    let supported: Vec<&'static str> = adapters::all().into_iter().map(|(name, _)| name).collect();
    if let Some(unknown) = requested.iter().find(|name| {
        !supported
            .iter()
            .any(|supported| supported == &name.as_str())
    }) {
        eprintln!(
            "unknown client {unknown}; supported: {}",
            supported.join(", ")
        );
        std::process::exit(2);
    }
    Some(requested)
}

fn render_scan_report(report_kind: &str, result: &ir::ScanResult) -> anyhow::Result<String> {
    match report_kind {
        "terminal" => Ok(report::render_scan_terminal(result)),
        "md" | "markdown" => Ok(report::render_scan_md(result)),
        "html" => Ok(report::render_scan_html(result)),
        "json" => Ok(serde_json::to_string_pretty(result)?),
        "sarif" => Ok(report::render_scan_sarif(result)),
        other => {
            anyhow::bail!("unsupported report format {other:?}; use terminal|md|html|json|sarif")
        }
    }
}

fn render_live_report(
    report_kind: &str,
    tools: &[ir::ExposedTool],
    findings: &[ir::Finding],
    edges: &[ir::FlowEdge],
) -> anyhow::Result<String> {
    match report_kind {
        "terminal" => Ok(report::render_live_terminal(tools, findings, edges)),
        "md" | "markdown" => Ok(report::render_live_md(tools, findings, edges)),
        "html" => Ok(report::render_live_html(tools, findings, edges)),
        "json" => Ok(serde_json::to_string_pretty(&serde_json::json!({
            "tools": tools,
            "findings": findings,
            "edges": edges
        }))?),
        "sarif" => Ok(report::render_live_sarif(tools, findings, edges)),
        other => {
            anyhow::bail!("unsupported report format {other:?}; use terminal|md|html|json|sarif")
        }
    }
}

fn emit(text: &str, output: Option<&Path>) -> anyhow::Result<()> {
    match output {
        Some(p) => {
            std::fs::write(p, text)?;
            eprintln!("wrote {}", p.display());
        }
        None => println!("{text}"),
    }
    Ok(())
}
