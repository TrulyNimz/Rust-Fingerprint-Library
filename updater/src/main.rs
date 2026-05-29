use clap::{Parser, Subcommand};
use fingerprint_updater::version::{current_version, DEFAULT_OWNER, DEFAULT_REPO, CURRENT_VERSION};

#[derive(Parser)]
#[command(name = "fingerprint-updater")]
#[command(about = "Self-updater for the Fingerprint SDK")]
#[command(version = CURRENT_VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// GitHub repository (owner/repo)
    #[arg(long, global = true, default_value_t = format!("{DEFAULT_OWNER}/{DEFAULT_REPO}"))]
    github_repo: String,

    /// Include pre-release versions
    #[arg(long, global = true, default_value_t = false)]
    pre_release: bool,

    /// Override install directory (default: exe's directory)
    #[arg(long, global = true)]
    install_dir: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Check if a newer version is available
    Check,
    /// Download and apply the latest update
    Update {
        /// Force re-download even if already up to date
        #[arg(long)]
        force: bool,
        /// Skip Ed25519 signature verification. DANGEROUS — only use for
        /// internal/dev builds where the release pipeline does not produce
        /// signatures yet.
        #[arg(long)]
        allow_unsigned: bool,
    },
    /// Roll back to the previous version from backup
    Rollback,
    /// Print the current version
    Version,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let (owner, repo) = parse_repo(&cli.github_repo);
    let current = current_version();
    let install_dir = cli
        .install_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(fingerprint_updater::detect_install_dir);

    let result = match cli.command {
        Commands::Version => {
            println!("fingerprint-updater v{CURRENT_VERSION}");
            Ok(())
        }
        Commands::Check => {
            cmd_check(&owner, &repo, &current, cli.pre_release).await
        }
        Commands::Update { force, allow_unsigned } => {
            cmd_update(
                &owner,
                &repo,
                &install_dir,
                &current,
                cli.pre_release,
                force,
                allow_unsigned,
            )
            .await
        }
        Commands::Rollback => {
            cmd_rollback(&install_dir)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn parse_repo(s: &str) -> (String, String) {
    let parts: Vec<&str> = s.splitn(2, '/').collect();
    if parts.len() == 2 {
        (parts[0].to_string(), parts[1].to_string())
    } else {
        eprintln!("Invalid --github-repo format. Expected 'owner/repo'.");
        std::process::exit(1);
    }
}

async fn cmd_check(
    owner: &str,
    repo: &str,
    current: &semver::Version,
    pre_release: bool,
) -> Result<(), fingerprint_updater::github::UpdateError> {
    println!("Current version: v{current}");
    println!("Checking {owner}/{repo} for updates...");

    match fingerprint_updater::github::check_for_update(owner, repo, current, pre_release).await? {
        Some(info) => {
            println!("Update available: v{}", info.version);
            println!("Release: {}", info.release_url);
            println!("\nRun `fingerprint-updater update` to install.");
        }
        None => {
            println!("Already up to date.");
        }
    }
    Ok(())
}

async fn cmd_update(
    owner: &str,
    repo: &str,
    install_dir: &std::path::Path,
    current: &semver::Version,
    pre_release: bool,
    force: bool,
    allow_unsigned: bool,
) -> Result<(), fingerprint_updater::github::UpdateError> {
    println!("Current version: v{current}");
    println!("Install directory: {}", install_dir.display());

    fingerprint_updater::perform_update(
        owner,
        repo,
        install_dir,
        current,
        pre_release,
        force,
        allow_unsigned,
    )
    .await?;

    Ok(())
}

fn cmd_rollback(
    install_dir: &std::path::Path,
) -> Result<(), fingerprint_updater::github::UpdateError> {
    println!("Install directory: {}", install_dir.display());
    fingerprint_updater::perform_rollback(install_dir)
}
