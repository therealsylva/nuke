use anyhow::{Context, Result, bail};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rand::RngCore;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use walkdir::WalkDir;
use zeroize::Zeroize;

const DB_NAME: &str = "nuke.db";
const CHUNK_SIZE: usize = 8 * 1024 * 1024;
const PROGRESS_THRESHOLD: u64 = 10 * 1024 * 1024;
const DAEMON_SLEEP_SECS: u64 = 60;

const BANNER: &str = r#"
███╗   ██╗██╗   ██╗██╗  ██╗███████╗
████╗  ██║██║   ██║██║ ██╔╝██╔════╝
██╔██╗ ██║██║   ██║█████╔╝ █████╗  
██║╚██╗██║██║   ██║██╔═██╗ ██╔══╝  
██║ ╚████║╚██████╔╝██║  ██╗███████╗
╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
Time-Delayed Secure Deletion v3.3
"#;

#[derive(Parser, Debug)]
#[command(name = "nuke", version, about, long_about = None)]
#[command(after_help = "Time formats: '2023-12-31' OR relative: '4d-3hr-90sec', '2weeks', '1h30m'.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Arm {
        target: PathBuf,
        datetime: String, 
        #[arg(short, long)]
        force: bool,
    },
    List,
    Disarm {
        target: PathBuf,
    },
    Status {
        target: PathBuf,
    },
    Wipe {
        target: PathBuf,
        #[arg(short, long)]
        force: bool,
    },
    Daemon,
}

fn main() -> Result<()> {
    println!("{}", BANNER.bright_red());
    let cli = Cli::parse();

    let conn = init_db()?;

    match cli.command {
        Commands::Arm { target, datetime, force } => cmd_arm(conn, target, datetime, force),
        Commands::List => cmd_list(conn),
        Commands::Disarm { target } => cmd_disarm(conn, target),
        Commands::Status { target } => cmd_status(conn, target),
        Commands::Wipe { target, force } => cmd_wipe(target, force),
        Commands::Daemon => cmd_daemon(conn),
    }
}

fn get_db_path() -> PathBuf {
    let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    let app_dir = config_dir.join("nuke");
    if !app_dir.exists() {
        fs::create_dir_all(&app_dir).unwrap_or_default();
    }
    app_dir.join(DB_NAME)
}

fn init_db() -> Result<Connection> {
    let path = get_db_path();
    let conn = Connection::open(path)?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_path TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            armed_at TEXT NOT NULL
        )",
        [],
    )?;

    Ok(conn)
}

fn cmd_arm(conn: Connection, target: PathBuf, datetime: String, force: bool) -> Result<()> {
    if !target.exists() {
        bail!("Target '{}' does not exist.", target.display());
    }
    
    let expires_dt = parse_smart_time(&datetime)?;
    let now = Local::now();
    if expires_dt <= now {
        bail!("Time must be in the future.");
    }

    let absolute_path = fs::canonicalize(&target)?;
    let target_str = absolute_path.display().to_string();

    println!("\n{} {}", "TARGET:".cyan(), target_str);
    println!(
        "{} {}",
        "DEADLINE:".red(),
        expires_dt.format("%Y-%m-%d %H:%M:%S").to_string().red()
    );

    if !force {
        println!("{}", "\nWARNING: This will PERMANENTLY DELETE the target on the specified date.".yellow());
        print!("Type 'ARM' to confirm: ");
        std::io::stdout().flush()?;
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        
        if input.trim() != "ARM" {
            println!("{}", "Aborted.".red());
            return Ok(());
        }
    }

    conn.execute(
        "INSERT INTO targets (target_path, expires_at, armed_at) VALUES (?1, ?2, ?3)",
        params![target_str, expires_dt.to_rfc3339(), now.to_rfc3339()],
    )?;

    println!("\n{}", "ARMED: Target successfully scheduled for secure deletion.".green());
    Ok(())
}

fn cmd_disarm(conn: Connection, target: PathBuf) -> Result<()> {
    let absolute_path = match fs::canonicalize(&target) {
        Ok(p) => p,
        Err(_) => bail!("Target path '{}' invalid or not found.", target.display()),
    };
    let target_str = absolute_path.display().to_string();

    match conn.execute(
        "DELETE FROM targets WHERE target_path = ?1",
        params![target_str],
    ) {
        Ok(rows) => {
            if rows > 0 {
                println!("{}", "DISARMED: Nuke sequence cancelled.".green());
            } else {
                println!("{}", "Target was not armed.".yellow());
            }
        }
        Err(e) => bail!("Database error: {}", e),
    }
    Ok(())
}

fn cmd_list(conn: Connection) -> Result<()> {
    let mut stmt = conn.prepare("SELECT target_path, expires_at FROM targets ORDER BY expires_at ASC")?;
    let target_iter = stmt.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
        ))
    })?;

    let mut found = false;
    println!("\n{} Armed Target(s):\n", "DATABASE:".dimmed());
    
    for target in target_iter {
        found = true;
        let (path, expires_str): (String, String) = target?;
        let expires: DateTime<Local> = DateTime::parse_from_rfc3339(&expires_str)?.into();
        let now = Local::now();
        let duration = expires.signed_duration_since(now);
        
        let time_str = if duration.num_seconds() > 0 {
            format!("(in {})", format_human_duration(duration))
        } else {
            "(DUE NOW)".red().to_string()
        };

        println!(
            "  {} {} → {} {}",
            "BOMB".red(),
            path.cyan(),
            expires.format("%Y-%m-%d %H:%M:%S").to_string().yellow(),
            time_str
        );
    }

    if !found {
        println!("No armed targets found in database.");
    }
    println!();
    Ok(())
}

fn cmd_status(conn: Connection, target: PathBuf) -> Result<()> {
    let absolute_path = match fs::canonicalize(&target) {
        Ok(p) => p,
        Err(_) => bail!("Target path '{}' invalid or not found.", target.display()),
    };
    let target_str = absolute_path.display().to_string();

    let mut stmt = conn.prepare("SELECT expires_at FROM targets WHERE target_path = ?1")?;
    
    let result = stmt.query_row(params![target_str], |row| {
        Ok(row.get::<_, String>(0)?)
    });

    match result {
        Ok(expires_str) => {
            let expires_dt: DateTime<Local> = DateTime::parse_from_rfc3339(&expires_str)?.into();
            let now = Local::now();
            println!("Target: {}", target_str.cyan());
            println!("Status: {}", "ARMED".red());
            println!("Nuke Date: {}", expires_dt.format("%Y-%m-%d %H:%M:%S").to_string().red());
            
            if now < expires_dt {
                println!("Time Remaining: {}", format_human_duration(expires_dt.signed_duration_since(now)));
            } else {
                println!("{}", "TIME ELAPSED - PENDING DETONATION".blink().red());
            }
        }
        Err(_) => println!("{}", "Target is not armed.".red()),
    }
    Ok(())
}

fn cmd_wipe(target: PathBuf, force: bool) -> Result<()> {
    if !target.exists() {
        bail!("Target '{}' does not exist.", target.display());
    }

    println!("\n{} {}", "TARGET:".red().bold(), target.display());

    if !force {
        println!("{}", "WARNING: This will PERMANENTLY and IMMEDIATELY destroy this data.".red());
        println!("{}", "It will be encrypted, the key will be zeroized, and the file will be deleted.".dimmed());
        println!("{}", "There is no undo.".blink().red());
        print!("\nType 'DESTROY' to confirm: ");
        std::io::stdout().flush()?;
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        
        if input.trim() != "DESTROY" {
            println!("{}", "\nAborted.".green());
            return Ok(());
        }
    }

    println!("Initiating secure wipe sequence...");
    
    match secure_wipe(target.as_path()) {
        Ok(_) => println!("\n{}", "TARGET DESTROYED. Securely wiped and unlinked.".green().bold()),
        Err(e) => {
            eprintln!("Error wiping {}: {}", target.display(), e);
            bail!("Wipe failed.");
        }
    }

    Ok(())
}

fn cmd_daemon(conn: Connection) -> Result<()> {
    println!("{} Daemon started. PID: {}", "[SYSTEMD]".dimmed(), std::process::id());
    println!("Watching database: {}", get_db_path().display().to_string().dimmed());
    println!("Press Ctrl+C to stop.\n");

    loop {
        let now = Local::now().to_rfc3339();
        
        let mut stmt = conn.prepare("SELECT id, target_path FROM targets WHERE expires_at <= ?1")?;
        
        let targets = stmt.query_map(params![now], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;

        let mut nuked_count = 0;

        for target in targets {
            let (id, path): (i64, String) = target?;
            let path_buf = PathBuf::from(&path);

            if path_buf.exists() {
                println!(
                    "\n{}",
                    format!("🚀 DETONATING: '{}' reached its end of life.", path).red()
                );

                match secure_wipe(&path_buf) {
                    Ok(_) => {
                        println!("{} {}", "✨".green(), "Encrypted, Verified, Key Zeroized, and Unlinked.".dimmed());
                        if let Err(e) = conn.execute("DELETE FROM targets WHERE id = ?1", params![id]) {
                            eprintln!("Warning: Failed to remove from DB {}: {}", id, e);
                        }
                        nuked_count += 1;
                    }
                    Err(e) => eprintln!("Error wiping {}: {}", path, e),
                }
            } else {
                println!("⚠️  Target {} no longer exists. Cleaning up DB.", path);
                let _ = conn.execute("DELETE FROM targets WHERE id = ?1", params![id]);
            }
        }

        if nuked_count > 0 {
            println!("\nCycle complete. {} target(s) destroyed. Sleeping...", nuked_count);
        }

        thread::sleep(Duration::from_secs(DAEMON_SLEEP_SECS));
    }
}

fn parse_smart_time(s: &str) -> Result<DateTime<Local>> {
    if let Ok(dt) = parse_datetime(s) {
        return Ok(dt);
    }

    let normalized = s.to_lowercase()
        .replace("hrs", "h").replace("hr", "h")
        .replace("mins", "m").replace("min", "m")
        .replace("secs", "s").replace("sec", "s")
        .replace("-", " ").replace(":", " ");

    if let Ok(dur) = humantime::parse_duration(&normalized) {
        let chrono_dur = chrono::Duration::from_std(dur)
            .context("Duration out of range")?;
        return Ok(Local::now() + chrono_dur);
    }

    anyhow::bail!("Could not parse date/duration. Try '4d-3h-30s' or '2023-12-31'")
}

fn parse_datetime(s: &str) -> Result<DateTime<Local>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) { return Ok(dt.into()); }
    
    let formats = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"];
    for fmt in formats {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Local.from_local_datetime(&ndt)
                .latest()
                .ok_or_else(|| anyhow::anyhow!("Invalid local time (does not exist due to DST)."));
        }
        if fmt == "%Y-%m-%d" {
             if let Ok(nd) = chrono::NaiveDate::parse_from_str(s, fmt) {
                let ndt = nd.and_hms_opt(0, 0, 0).unwrap();
                return Local.from_local_datetime(&ndt)
                    .latest()
                    .ok_or_else(|| anyhow::anyhow!("Invalid local time."));
            }
        }
    }
    anyhow::bail!("Could not parse date/duration. Try '4d-3h-30s' or '2023-12-31'")
}

fn format_human_duration(duration: chrono::Duration) -> String {
    let total_secs = duration.num_seconds().abs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    format!("{}d {}h {}m", days, hours, minutes)
}

fn secure_wipe(path: &Path) -> Result<()> {
    if path.is_dir() {
        let mut paths: Vec<PathBuf> = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .map(|e| e.path().to_path_buf())
            .collect();
        
        paths.sort_by(|a, b| b.cmp(a)); 

        for p in paths {
            if p == path { continue; } 
            secure_wipe(&p)?;
        }
        
        fs::remove_dir(path)?;
    } else {
        let metadata = fs::metadata(path)?;
        let file_size = metadata.len();

        if file_size == 0 {
            fs::remove_file(path)?;
            return Ok(());
        }

        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut nonce);

        let original_hash = hash_file_start(path)?;

        let temp_path = path.with_extension(format!("nuke_tmp_{}", rand::random::<u32>()));

        let pb = if file_size > PROGRESS_THRESHOLD {
            let pb = ProgressBar::new(file_size);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
                .progress_chars("#>-"));
            pb.set_message("Encrypting");
            Some(pb)
        } else {
            None
        };

        {
            let mut reader = File::open(path)?;
            let mut writer = File::create(&temp_path)?;
            let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
            
            let mut buffer = vec![0u8; CHUNK_SIZE];
            
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 { break; }
                
                cipher.apply_keystream(&mut buffer[..n]);
                writer.write_all(&buffer[..n])?;
                
                if let Some(ref p) = pb {
                    p.inc(n as u64);
                }
            }
            
            writer.flush()?;
            writer.sync_all()?;
            
            buffer.zeroize();
            if let Some(ref p) = pb {
                p.finish_with_message("Encrypted");
            }
        }
        
        let encrypted_hash = hash_file_start(&temp_path)?;
        if original_hash == encrypted_hash {
            bail!("Encryption verification failed: Data appears unchanged.");
        }

        fs::rename(&temp_path, path)?;
        
        key.zeroize();
        nonce.zeroize();
        
        fs::remove_file(path)?;
    }

    Ok(())
}

fn hash_file_start(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 1024];
    let n = file.read(&mut buffer)?;
    
    let mut hasher = Sha256::new();
    hasher.update(&buffer[..n]);
    
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Ok(arr)
}