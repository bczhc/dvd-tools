//! 单文件 DVD 镜像数据填充：把数据直接填入 dis 镜像 / 从镜像取回。Rust 移植自 dvd_hide.py。
//!
//! 用法:
//!     dvd-embed embed    DIS_ISO  DATA_FILE  OUTPUT_IMAGE
//!     dvd-embed extract  IMAGE_FILE             (数据写到 stdout)
//!     dvd-embed capacity DIS_ISO

use std::fs::File;
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use aes::Aes256;
use clap::{Parser, Subcommand};
use ctr::cipher::{KeyIvInit, StreamCipher};
use dvd_tools::{SECTOR, masks, preset_index};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

// ---------------- 常量 ----------------
const ESC: u8 = 0x5C; // 转义前缀（不是特殊字节）
const MAGIC: &[u8] = b"DH01"; // 头部魔数，用于校验
const HEADER_LEN: usize = 12; // MAGIC(4) + 长度(8)
const CHUNK_SECTORS: usize = 2048; // 每块 2048 扇区 = 4 MiB
const CHUNK_SIZE: usize = CHUNK_SECTORS * SECTOR;

const KEY: [u8; 32] = [0; 32]; // AES-256 key，全零
const NONCE: [u8; 8] = [0; 8]; // CTR nonce，全零

// ---------------- AES-256-CTR（key/nonce 全零，自逆，长度不变） ----------------
fn ctr_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&NONCE);
    iv
}

/// CTR：加密 == 解密 == 数据 XOR 密钥流。原地操作。分块做以便显示进度（label 非空时）。
fn scramble(data: &mut [u8], label: Option<&str>, prog: &mut Progress) {
    let mut cipher = Aes256Ctr::new(&KEY.into(), &ctr_iv().into());
    let total = data.len();
    let step = 1usize << 22; // 4 MiB
    let Some(label) = label else {
        cipher.apply_keystream(data);
        return;
    };
    if total <= step {
        cipher.apply_keystream(data);
        return;
    }
    let mut i = 0usize;
    while i < total {
        let end = (i + step).min(total);
        cipher.apply_keystream(&mut data[i..end]);
        i = end;
        prog.update(i as u64, total as u64, label);
    }
    prog.end();
}

// ---------------- 转义 ----------------
/// 嵌入流里不能出现的字节：{A5, 92, 9B}。
fn is_special(b: u8) -> bool {
    matches!(b, 0xA5 | 0x92 | 0x9B)
}

fn needs_escape(b: u8) -> bool {
    matches!(b, 0xA5 | 0x92 | 0x9B | 0x5C)
}

/// 转义：A5->5C00, 92->5C01, 9B->5C02, 5C->5C5C；其余原样。分块做以便显示进度（label 非空时）。
fn escape(data: &[u8], label: Option<&str>, prog: &mut Progress) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    // 先数出总输出长度（每个命中字节多出 1 字节）
    let extra = data.iter().filter(|&&b| needs_escape(b)).count();
    let mut out = Vec::with_capacity(data.len() + extra);

    let step = 8 * 1024 * 1024; // 8 MiB
    let total = data.len();
    let mut done = 0usize;
    for chunk in data.chunks(step) {
        for &b in chunk {
            match b {
                0xA5 => out.extend_from_slice(&[ESC, 0x00]),
                0x92 => out.extend_from_slice(&[ESC, 0x01]),
                0x9B => out.extend_from_slice(&[ESC, 0x02]),
                0x5C => out.extend_from_slice(&[ESC, 0x5C]),
                _ => out.push(b),
            }
        }
        done += chunk.len();
        if let Some(l) = label {
            prog.update(done as u64, total as u64, l);
        }
    }
    if label.is_some() {
        prog.end();
    }
    out
}

// ---------------- 进度条（写 stderr） ----------------
struct Progress {
    tty: bool,
    quiet: bool,
    bar_active: bool,
    last_bucket: i64,
}

impl Progress {
    fn new(quiet: bool) -> Self {
        Progress {
            tty: io::stderr().is_terminal(),
            quiet,
            bar_active: false,
            last_bucket: -1,
        }
    }

    fn update(&mut self, done: u64, total: u64, label: &str) {
        if self.quiet || total == 0 {
            return;
        }
        if self.tty {
            self.bar_active = true;
            let pct = (done as f64 * 100.0 / total as f64).min(100.0);
            let filled = (40.0 * done.min(total) as f64 / total as f64) as usize;
            let bar = "#".repeat(filled) + &"-".repeat(40 - filled);
            eprint!("\r{} [{}] {:5.1}%  {}/{} 字节", label, bar, pct, done, total);
            let _ = io::stderr().flush();
        } else {
            let bucket = (done * 20 / total) as i64;
            if bucket != self.last_bucket {
                self.last_bucket = bucket;
                let pct = (done as f64 * 100.0 / total as f64).min(100.0);
                eprintln!("{} {:5.1}%  {}/{} 字节", label, pct, done, total);
            }
        }
    }

    fn end(&mut self) {
        if self.tty && self.bar_active {
            eprintln!();
        }
        self.bar_active = false;
        self.last_bucket = -1;
    }
}

// ---------------- 正向 ----------------
fn embed(dis_path: &Path, data: Vec<u8>, out_path: &Path, quiet: bool) -> Result<(usize, usize, usize), String> {
    let masks = masks();
    let mut prog = Progress::new(quiet);

    let n = data.len();
    let mut b = data;
    scramble(&mut b, Some("加密中"), &mut prog);
    let nb = b.len();

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&(nb as u64).to_le_bytes());

    let cb = escape(&b, Some("转义中"), &mut prog);
    let mut c = escape(&header, None, &mut prog);
    c.extend_from_slice(&cb);
    let nc = c.len();

    let total_size = std::fs::metadata(dis_path).map_err(|e| e.to_string())?.len();
    let fin = File::open(dis_path).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(fin);
    let fout = File::create(out_path).map_err(|e| e.to_string())?;
    let mut writer = BufWriter::new(fout);

    let mut si0: i64 = 0;
    let mut c_pos = 0usize;
    let mut read_bytes = 0u64;
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK_SIZE + SECTOR);

    loop {
        buf.resize(CHUNK_SIZE, 0);
        let nread = reader.read(&mut buf).map_err(|e| e.to_string())?;
        if nread == 0 {
            break;
        }
        read_bytes += nread as u64;
        buf.truncate(nread);
        let pad = (SECTOR - nread % SECTOR) % SECTOR; // 末扇区补零
        if pad > 0 {
            buf.resize(nread + pad, 0);
        }
        let n_sectors = buf.len() / SECTOR;

        for j in 0..n_sectors {
            let mask = &masks[preset_index(0, si0 + j as i64)];
            let base = j * SECTOR;
            for i in 0..SECTOR {
                let raw = buf[base + i];
                let a = raw ^ mask[i];
                let v = if !is_special(a) && c_pos < nc {
                    let byte = c[c_pos];
                    c_pos += 1;
                    byte
                } else {
                    a
                };
                buf[base + i] = v ^ mask[i];
            }
        }
        writer.write_all(&buf).map_err(|e| e.to_string())?;
        si0 += n_sectors as i64;
        prog.update(read_bytes, total_size, "嵌入中");
    }

    prog.end();
    if c_pos != nc {
        return Err(format!(
            "错误: 数据放不下 —— 需要 {} 个槽位，镜像只提供 {} 个（可用容量约 = 镜像里非 A5/92/9B 的字节数）",
            nc, c_pos
        ));
    }
    Ok((n, nb, nc))
}

// ---------------- 逆向 ----------------
fn extract(image_path: &Path, quiet: bool) -> Result<usize, String> {
    let masks = masks();
    let mut prog = Progress::new(quiet);

    // 设备（如 /dev/sr0）的 size 是 0，拿不到就当 0（进度条不显示）。
    let total_size = std::fs::metadata(image_path).map(|m| m.len()).unwrap_or(0);
    let fin = File::open(image_path).map_err(|e| format!("错误: 打开 {} 失败: {e}", image_path.display()))?;
    let mut reader = BufReader::new(fin);
    let mut out = io::stdout().lock();

    let mut header: Vec<u8> = Vec::with_capacity(HEADER_LEN);
    let mut remaining = 0usize; // 还需解密的密文字节数
    let mut data_len = 0usize;
    let mut cipher: Option<Aes256Ctr> = None;
    let mut decrypt_buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut pending = false;

    let mut si0: i64 = 0;
    let mut read_bytes = 0u64;
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK_SIZE + SECTOR);

    loop {
        buf.resize(CHUNK_SIZE, 0);
        let nread = reader.read(&mut buf).map_err(|e| format!("错误: 读取失败: {e}"))?;
        if nread == 0 {
            break;
        }
        read_bytes += nread as u64;
        buf.truncate(nread);
        let pad = (SECTOR - nread % SECTOR) % SECTOR;
        if pad > 0 {
            buf.resize(nread + pad, 0);
        }
        let n_sectors = buf.len() / SECTOR;

        for j in 0..n_sectors {
            let mask = &masks[preset_index(0, si0 + j as i64)];
            let base = j * SECTOR;
            for i in 0..SECTOR {
                let d = buf[base + i] ^ mask[i];
                if is_special(d) {
                    continue;
                }

                // 反转义出一个字节 b
                let b = if pending {
                    pending = false;
                    match d {
                        0x00 => 0xA5,
                        0x01 => 0x92,
                        0x02 => 0x9B,
                        0x5C => 0x5C,
                        _ => return Err(format!("错误: 非法转义序列 5C {:02x}（镜像可能损坏）", d)),
                    }
                } else if d == ESC {
                    pending = true;
                    continue;
                } else {
                    d
                };

                if header.len() < HEADER_LEN {
                    header.push(b);
                    if header.len() == HEADER_LEN {
                        if &header[..MAGIC.len()] != MAGIC {
                            return Err(
                                "错误: 镜像里没有数据魔数（不是本程序嵌入的镜像，或 --offset 不对）".to_string(),
                            );
                        }
                        let mut le = [0u8; 8];
                        le.copy_from_slice(&header[MAGIC.len()..HEADER_LEN]);
                        data_len = u64::from_le_bytes(le) as usize;
                        remaining = data_len;
                        cipher = Some(Aes256Ctr::new(&KEY.into(), &ctr_iv().into()));
                        if remaining == 0 {
                            out.flush().map_err(|e| format!("错误: 写 stdout 失败: {e}"))?;
                            prog.end();
                            return Ok(0);
                        }
                    }
                } else {
                    // 密文字节：流式解密并写到 stdout
                    decrypt_buf.push(b);
                    remaining -= 1;
                    if decrypt_buf.len() >= 64 * 1024 || remaining == 0 {
                        cipher.as_mut().unwrap().apply_keystream(&mut decrypt_buf);
                        out.write_all(&decrypt_buf).map_err(|e| format!("错误: 写 stdout 失败: {e}"))?;
                        decrypt_buf.clear();
                    }
                    if remaining == 0 {
                        out.flush().map_err(|e| format!("错误: 写 stdout 失败: {e}"))?;
                        prog.end();
                        return Ok(data_len);
                    }
                }
            }
        }
        si0 += n_sectors as i64;
        prog.update(read_bytes, total_size, "提取中");
    }

    prog.end();
    Err("错误: 镜像里数据不完整（流提前结束）".to_string())
}

// ---------------- 容量 ----------------
fn capacity(dis_path: &Path, quiet: bool) -> Result<(u64, u64), String> {
    let masks = masks();
    let mut prog = Progress::new(quiet);

    let total_size = std::fs::metadata(dis_path).map_err(|e| e.to_string())?.len();
    let fin = File::open(dis_path).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(fin);

    let mut slots = 0u64;
    let mut total = 0u64;
    let mut read_bytes = 0u64;
    let mut si0: i64 = 0;
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK_SIZE + SECTOR);

    loop {
        buf.resize(CHUNK_SIZE, 0);
        let nread = reader.read(&mut buf).map_err(|e| e.to_string())?;
        if nread == 0 {
            break;
        }
        read_bytes += nread as u64;
        buf.truncate(nread);
        let pad = (SECTOR - nread % SECTOR) % SECTOR;
        if pad > 0 {
            buf.resize(nread + pad, 0);
        }
        let n_sectors = buf.len() / SECTOR;

        for j in 0..n_sectors {
            let mask = &masks[preset_index(0, si0 + j as i64)];
            let base = j * SECTOR;
            for i in 0..SECTOR {
                let a = buf[base + i] ^ mask[i];
                if !is_special(a) {
                    slots += 1;
                }
            }
        }
        total += buf.len() as u64;
        si0 += n_sectors as i64;
        prog.update(read_bytes, total_size, "统计中");
    }

    prog.end();
    Ok((slots, total))
}

// ---------------- 命令行 ----------------
#[derive(Parser)]
#[command(name = "dvd-embed", version, about = "单文件 DVD 镜像数据填充")]
struct Cli {
    /// 不显示进度
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 把数据直接填入 dis 镜像
    Embed {
        /// 载体镜像
        dis: PathBuf,
        /// 要填入的数据文件
        data: PathBuf,
        /// 输出镜像文件
        output: PathBuf,
    },
    /// 从镜像取回数据（写到 stdout）
    Extract {
        /// 含数据的镜像（可以是设备，如 /dev/sr0）
        image: PathBuf,
    },
    /// 预估能填充多少数据
    Capacity {
        /// 载体镜像
        dis: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let quiet = cli.quiet;
    match cli.command {
        Command::Embed { dis, data, output } => {
            let data_bytes = match std::fs::read(&data) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("错误: 读取数据文件失败: {e}");
                    std::process::exit(1);
                }
            };
            match embed(&dis, data_bytes, &output, quiet) {
                Ok((n, nb, nc)) => {
                    println!("完成: {} + {} -> {}", dis.display(), data.display(), output.display());
                    println!("  数据 {n} 字节 → B {nb} 字节 → C {nc} 字节");
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Extract { image } => match extract(&image, quiet) {
            Ok(n) => eprintln!("完成: 从 {} 提取 {n} 字节（写到 stdout）", image.display()),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        },
        Command::Capacity { dis } => match capacity(&dis, quiet) {
            Ok((slots, total)) => {
                let est = (slots as i128 * 64 / 65) - HEADER_LEN as i128;
                println!(
                    "镜像: {}（{total} 字节，{} 扇区）",
                    dis.display(),
                    total / SECTOR as u64
                );
                println!("可用槽位（非 A5/92/9B 的字节数）: {slots}");
                println!("预估可填充数据大小: 约 {est} 字节（{:.3} MiB）", est as f64 / 1048576.0);
                println!("  （= 槽位 - 12 字节头 - 约 1/64 转义膨胀；实际取决于数据分布）");
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        },
    }
}
