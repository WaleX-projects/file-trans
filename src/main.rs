//! fileshare: send files directly from one computer to another.
//!
//!   Computer A (the one that receives):   fileshare receive
//!   Computer B (the one that sends):      fileshare send <TICKET> report.pdf movie.mkv
//!
//! No server of ours is involved. iroh finds the other computer and opens an
//! encrypted QUIC connection straight to it (through the office WiFi if you are
//! on the same network, or over the internet if not).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use iroh::endpoint::{Connection, Incoming, RecvStream, SendStream, presets};
use iroh::{Endpoint, SecretKey};
use iroh_tickets::endpoint::EndpointTicket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Name of our "language". Both sides must use the same one or the connection is refused.
const ALPN: &[u8] = b"fileshare/1";
/// We move files in 64 KB pieces so a 5 GB movie never has to fit in memory.
const CHUNK: usize = 64 * 1024;
/// Single-byte replies the receiver sends back.
const OK: u8 = 0;
const WRONG_CODE: u8 = 1;
const DONE: u8 = 2;

#[derive(Parser)]
#[command(name = "fileshare", about = "Send files directly between two computers")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Wait for files. Prints a ticket that senders use to find this computer.
    Receive {
        /// Where received files are saved (default: Downloads/FileShare)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Send one or more files to a receiver.
    Send {
        /// The ticket printed by `fileshare receive`
        ticket: String,
        /// Files to send
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Receive { dir } => {
            let dir = dir
                .or_else(|| dirs::download_dir().map(|d| d.join("FileShare")))
                .unwrap_or_else(|| PathBuf::from("FileShare"));
            receive(dir).await
        }
        Cmd::Send { ticket, files } => send(ticket, files).await,
    }
}

// ============================================================ identity

/// The receiver keeps the same identity (key + pairing code) between runs,
/// so colleagues can reuse the same ticket and only pair once.
fn config_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("FILESHARE_HOME") {
        Some(p) => PathBuf::from(p),
        None => dirs::config_dir().context("no config folder")?.join("fileshare"),
    };
    std::fs::create_dir_all(&base)?;
    Ok(base)
}

fn load_or_create_key() -> Result<SecretKey> {
    let path = config_dir()?.join("secret.key");
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(SecretKey::from_bytes(&arr));
        }
    }
    let key = SecretKey::generate();
    std::fs::write(&path, key.to_bytes())?;
    Ok(key)
}

/// A random pairing code. Only people who have the ticket (which contains the
/// code) can send files, so strangers on the same WiFi cannot dump files on you.
fn load_or_create_code() -> Result<String> {
    let path = config_dir()?.join("code.txt");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim().to_string();
        if !s.is_empty() {
            return Ok(s);
        }
    }
    let b = SecretKey::generate().to_bytes(); // reuse the key generator as a secure random source
    let n = u64::from_le_bytes(b[..8].try_into().unwrap()) % 10_000_000_000;
    let code = format!("{n:010}");
    std::fs::write(&path, &code)?;
    Ok(code)
}

// ============================================================ receiver

async fn receive(dir: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&dir)?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(load_or_create_key()?)
        .alpns(vec![ALPN.to_vec()]) // "I accept connections speaking fileshare/1"
        .bind()
        .await?;

    // Give it a few seconds to reach the relay (needs internet). If there is no
    // internet we carry on: the ticket still contains the local IP addresses,
    // so computers on the same WiFi/cable can still connect.
    let _ = tokio::time::timeout(Duration::from_secs(5), endpoint.online()).await;

    let code = load_or_create_code()?;
    let ticket = format!("{}_{}", EndpointTicket::new(endpoint.addr()), code);

    println!("Ready. Saving files to: {}\n", dir.display());
    println!("Give this ticket to the people who should send you files:\n");
    println!("{ticket}\n");
    println!("On their computer:  fileshare send <ticket> <file>");
    println!("Waiting for files... (Ctrl+C to stop)\n");

    // Accept connections forever. Each sender is handled in its own task.
    while let Some(incoming) = endpoint.accept().await {
        let (dir, code) = (dir.clone(), code.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, dir, code).await {
                eprintln!("connection error: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_connection(incoming: Incoming, dir: PathBuf, code: String) -> Result<()> {
    let conn = incoming.accept()?.await?;
    println!("Connected: {}", conn.remote_id().fmt_short());
    // One connection can carry many files; each file uses its own stream.
    while let Ok((send, recv)) = conn.accept_bi().await {
        if let Err(e) = receive_file(send, recv, &dir, &code).await {
            eprintln!("  transfer failed: {e:#}");
        }
    }
    Ok(())
}

async fn receive_file(
    mut send: SendStream,
    mut recv: RecvStream,
    dir: &Path,
    code: &str,
) -> Result<()> {
    // Header = pairing code, file name, file size.
    let got_code = read_string(&mut recv).await?;
    let name = read_string(&mut recv).await?;
    let mut size_bytes = [0u8; 8];
    recv.read_exact(&mut size_bytes).await?;
    let size = u64::from_be_bytes(size_bytes);

    if got_code != code {
        send.write_all(&[WRONG_CODE]).await?;
        send.finish()?;
        bail!("rejected a sender with the wrong code");
    }

    // Never trust the name we were sent: keep only the last part so nobody can
    // write outside our folder with something like "..\..\Windows\x.exe".
    let safe_name = Path::new(&name)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|n| !n.is_empty())
        .context("bad file name")?;
    let final_path = unique_path(dir, &safe_name);
    let tmp_path = final_path.with_extension("part");

    send.write_all(&[OK]).await?; // tell the sender: go ahead
    println!("Receiving {safe_name} ({})", human(size));

    let mut file = tokio::fs::File::create(&tmp_path).await?;
    let mut buf = vec![0u8; CHUNK];
    let mut remaining = size;
    let mut last_pct = 101;
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = recv
            .read(&mut buf[..want])
            .await?
            .ok_or_else(|| anyhow!("sender disconnected early"))?;
        file.write_all(&buf[..n]).await?;
        remaining -= n as u64;
        last_pct = show_progress(size - remaining, size, last_pct);
    }
    file.flush().await?;
    drop(file);
    // Only rename once complete, so a half-received file never looks finished.
    tokio::fs::rename(&tmp_path, &final_path).await?;
    println!("\n  saved: {}", final_path.display());

    send.write_all(&[DONE]).await?;
    send.finish()?;
    Ok(())
}

/// "movie.mkv" -> "movie (1).mkv" if it already exists.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let stem = Path::new(name).file_stem().unwrap().to_string_lossy().to_string();
    let ext = Path::new(name)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    (1..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .unwrap()
}

// ============================================================ sender

async fn send(ticket: String, files: Vec<PathBuf>) -> Result<()> {
    // The ticket is "<where to find the receiver>_<pairing code>"
    let (addr_part, code) = ticket.trim().rsplit_once('_').context("that ticket looks wrong")?;
    let ticket: EndpointTicket = addr_part.parse().map_err(|e| anyhow!("bad ticket: {e}"))?;

    let endpoint = Endpoint::bind(presets::N0).await?;
    println!("Connecting...");
    let conn = endpoint
        .connect(ticket.endpoint_addr().clone(), ALPN)
        .await
        .context("could not reach the receiver (is `fileshare receive` running?)")?;

    // Send every file, but always close the connection cleanly afterwards,
    // even if one of the files failed.
    let mut result = Ok(());
    for path in &files {
        result = send_file(&conn, path, code).await;
        if result.is_err() {
            break;
        }
    }
    conn.close(0u32.into(), b"all done");
    endpoint.close().await;
    result
}

async fn send_file(conn: &Connection, path: &Path, code: &str) -> Result<()> {
    let name = path
        .file_name()
        .context("not a file")?
        .to_string_lossy()
        .to_string();
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("cannot open {}", path.display()))?;
    let size = file.metadata().await?.len();

    let (mut send, mut recv) = conn.open_bi().await?;
    write_string(&mut send, code).await?;
    write_string(&mut send, &name).await?;
    send.write_all(&size.to_be_bytes()).await?;

    // Wait for the receiver's verdict before sending any data.
    let mut status = [0u8; 1];
    recv.read_exact(&mut status).await?;
    if status[0] == WRONG_CODE {
        bail!("the receiver rejected the pairing code");
    }

    println!("Sending {name} ({})", human(size));
    let mut buf = vec![0u8; CHUNK];
    let mut sent = 0u64;
    let mut last_pct = 101;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        send.write_all(&buf[..n]).await?;
        sent += n as u64;
        last_pct = show_progress(sent, size, last_pct);
    }
    send.finish()?;

    // Wait until the receiver confirms the file is safely on its disk.
    let mut done = [0u8; 1];
    recv.read_exact(&mut done).await?;
    if done[0] != DONE {
        bail!("receiver did not confirm the file");
    }
    println!("\n  delivered.");
    Ok(())
}

// ============================================================ small helpers

/// Strings are sent as: 2-byte length, then the bytes.
async fn write_string(send: &mut SendStream, s: &str) -> Result<()> {
    send.write_all(&(s.len() as u16).to_be_bytes()).await?;
    send.write_all(s.as_bytes()).await?;
    Ok(())
}

async fn read_string(recv: &mut RecvStream) -> Result<String> {
    let mut len = [0u8; 2];
    recv.read_exact(&mut len).await?;
    let mut bytes = vec![0u8; u16::from_be_bytes(len) as usize];
    recv.read_exact(&mut bytes).await?;
    Ok(String::from_utf8(bytes)?)
}

fn show_progress(done: u64, total: u64, last_pct: u64) -> u64 {
    let pct = if total == 0 { 100 } else { done * 100 / total };
    if pct != last_pct {
        print!("\r  {pct}%  ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
    pct
}

fn human(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", units[i])
}
