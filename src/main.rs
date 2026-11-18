use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use syncforge::engine::{
    init_repository, prune_repository, restore_snapshot, run_backup, stats_report, verify_repository,
};
use syncforge::storage::S3Config;

#[derive(Parser)]
#[command(name = "syncforge", version, about = "Encrypted, chunked, deduplicated backup and snapshot platform")]
struct Cli {
    #[arg(long, env = "SYNCFORGE_REPO", default_value = "./vault")]
    repo: PathBuf,

    #[arg(long, env = "SYNCFORGE_PASSPHRASE", default_value = "dev-passphrase")]
    passphrase: String,

    #[arg(long, env = "SYNCFORGE_S3_ENDPOINT", default_value = "")]
    s3_endpoint: String,
    #[arg(long, env = "SYNCFORGE_S3_BUCKET", default_value = "")]
    s3_bucket: String,
    #[arg(long, env = "SYNCFORGE_S3_REGION", default_value = "us-east-1")]
    s3_region: String,
    #[arg(long, env = "SYNCFORGE_S3_ACCESS_KEY", default_value = "")]
    s3_access_key: String,
    #[arg(long, env = "SYNCFORGE_S3_SECRET_KEY", default_value = "")]
    s3_secret_key: String,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new encrypted SyncForge repository
    Init {
        #[arg(long, default_value_t = 262144)]
        chunk_size: usize,
    },
    /// Create a full, incremental, or differential backup snapshot
    Backup {
        #[arg(long, default_value = "default")]
        profile: String,
        #[arg(long, value_delimiter = ',')]
        source: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        exclude: Vec<String>,
        #[arg(long, default_value = "incremental")]
        mode: String,
        #[arg(long)]
        resume: bool,
    },
    /// List backup snapshots recorded in catalog
    Snapshots,
    /// Restore a full snapshot or matching file/prefix
    Restore {
        snapshot_id: String,
        dest: PathBuf,
        #[arg(long)]
        only: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Decrypt and verify SHA-256 integrity of all chunks
    Verify,
    /// Prune old snapshots and garbage-collect unreferenced chunks
    Prune {
        #[arg(long, default_value_t = 5)]
        keep_last: usize,
    },
    /// Output repository deduplication and storage statistics as JSON
    Stats,
    /// Run background agent loop on a fixed interval
    Daemon {
        #[arg(long, default_value = "default")]
        profile: String,
        #[arg(long, value_delimiter = ',', required = true)]
        source: Vec<PathBuf>,
        #[arg(long, default_value_t = 300)]
        interval_sec: u64,
        #[arg(long, default_value_t = 5)]
        keep_last: usize,
    },
}

fn build_s3(cli: &Cli) -> Option<S3Config> {
    if cli.s3_endpoint.trim().is_empty() || cli.s3_bucket.trim().is_empty() {
        return None;
    }
    Some(S3Config {
        endpoint: cli.s3_endpoint.clone(),
        bucket: cli.s3_bucket.clone(),
        region: cli.s3_region.clone(),
        access_key: cli.s3_access_key.clone(),
        secret_key: cli.s3_secret_key.clone(),
    })
}

fn main() {
    let cli = Cli::parse();
    let s3 = build_s3(&cli);
    let res: Result<(), String> = match &cli.cmd {
        Commands::Init { chunk_size } => init_repository(&cli.repo, &cli.passphrase, *chunk_size).map(|m| {
            println!("{}", serde_json::to_string_pretty(&m).unwrap());
        }),
        Commands::Backup { profile, source, exclude, mode, resume } => {
            run_backup(&cli.repo, &cli.passphrase, s3, profile, source, exclude, mode, *resume).map(|s| {
                println!("{}", serde_json::to_string_pretty(&s).unwrap());
            })
        }
        Commands::Snapshots => syncforge::engine::open_repo(&cli.repo, &cli.passphrase, s3)
            .and_then(|(_, _, cat, _)| cat.list_snapshots())
            .map(|snaps| println!("{}", serde_json::to_string_pretty(&snaps).unwrap())),
        Commands::Restore { snapshot_id, dest, only, dry_run } => {
            restore_snapshot(&cli.repo, &cli.passphrase, s3, snapshot_id, dest, only.as_deref(), *dry_run).map(|r| {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
            })
        }
        Commands::Verify => verify_repository(&cli.repo, &cli.passphrase, s3).map(|v| {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            if !v.healthy {
                std::process::exit(2);
            }
        }),
        Commands::Prune { keep_last } => prune_repository(&cli.repo, &cli.passphrase, s3, *keep_last).map(|(s, c)| {
            println!("{{\"snapshots_removed\":{s},\"chunks_collected\":{c}}}");
        }),
        Commands::Stats => stats_report(&cli.repo, &cli.passphrase, s3).map(|st| {
            println!("{}", serde_json::to_string_pretty(&st).unwrap());
        }),
        Commands::Daemon { profile, source, interval_sec, keep_last } => {
            loop {
                match run_backup(&cli.repo, &cli.passphrase, s3.clone(), profile, source, &[], "incremental", true) {
                    Ok(snap) => {
                        let _ = prune_repository(&cli.repo, &cli.passphrase, s3.clone(), *keep_last);
                        println!("daemon backup complete: {}", snap.id);
                    }
                    Err(e) => eprintln!("daemon backup error: {e}"),
                }
                thread::sleep(Duration::from_secs(*interval_sec));
            }
        }
    };

    if let Err(err) = res {
        eprintln!("syncforge error: {err}");
        std::process::exit(1);
    }
}
