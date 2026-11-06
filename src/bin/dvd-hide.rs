//! 单文件 DVD 镜像数据填充：把数据直接填入 dis 镜像 / 从镜像取回。Rust 移植自 dvd_hide.py。
//!
//! 用法:
//!     dvd-hide embed    DIS_ISO  DATA_FILE  OUTPUT_IMAGE  [--offset N]
//!     dvd-hide extract  IMAGE_FILE  OUTPUT_DATA           [--offset N]
//!     dvd-hide capacity DIS_ISO                            [--offset N]

use std::fs::File;
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Write};

use aes::Aes256;
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
    bar_active: bool,
    last_bucket: i64,
}

impl Progress {
    fn new() -> Self {
        Progress {
            tty: io::stderr().is_terminal(),
            bar_active: false,
            last_bucket: -1,
        }
    }

    fn update(&mut self, done: u64, total: u64, label: &str) {
        if total == 0 {
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
fn embed(dis_path: &str, data: Vec<u8>, out_path: &str, offset: i64) -> Result<(usize, usize, usize), String> {
    let masks = masks();
    let mut prog = Progress::new();

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
            let mask = &masks[preset_index(offset, si0 + j as i64)];
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
fn extract(image_path: &str, out_path: &str, offset: i64) -> Result<usize, String> {
    let masks = masks();
    let mut prog = Progress::new();

    let total_size = std::fs::metadata(image_path).map_err(|e| e.to_string())?.len();
    let fin = File::open(image_path).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(fin);

    let mut out: Vec<u8> = Vec::new();
    let mut pending = false;
    let mut length: Option<u64> = None;
    let mut needed = HEADER_LEN;

    let mut si0: i64 = 0;
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
        let pad = (SECTOR - nread % SECTOR) % SECTOR;
        if pad > 0 {
            buf.resize(nread + pad, 0);
        }
        let n_sectors = buf.len() / SECTOR;

        for j in 0..n_sectors {
            let mask = &masks[preset_index(offset, si0 + j as i64)];
            let base = j * SECTOR;
            for i in 0..SECTOR {
                let d = buf[base + i] ^ mask[i];
                if is_special(d) {
                    continue;
                }
                if pending {
                    let val = match d {
                        0x00 => 0xA5,
                        0x01 => 0x92,
                        0x02 => 0x9B,
                        0x5C => 0x5C,
                        _ => return Err(format!("错误: 非法转义序列 5C {:02x}（镜像可能损坏）", d)),
                    };
                    out.push(val);
                    pending = false;
                } else if d == ESC {
                    pending = true;
                } else {
                    out.push(d);
                }

                if length.is_none() && out.len() >= HEADER_LEN {
                    if &out[..MAGIC.len()] != MAGIC {
                        return Err(
                            "错误: 镜像里没有数据魔数（不是本程序嵌入的镜像，或 --offset 不对）".to_string(),
                        );
                    }
                    let mut le = [0u8; 8];
                    le.copy_from_slice(&out[MAGIC.len()..HEADER_LEN]);
                    let l = u64::from_le_bytes(le);
                    length = Some(l);
                    needed = HEADER_LEN.saturating_add(l as usize);
                }

                if length.is_some() && out.len() >= needed {
                    prog.end();
                    let mut data = out[HEADER_LEN..needed].to_vec();
                    scramble(&mut data, Some("解密中"), &mut prog); // CTR 自逆
                    std::fs::write(out_path, &data).map_err(|e| e.to_string())?;
                    return Ok(data.len());
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
fn capacity(dis_path: &str, offset: i64) -> Result<(u64, u64), String> {
    let masks = masks();
    let mut prog = Progress::new();

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
            let mask = &masks[preset_index(offset, si0 + j as i64)];
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
fn usage() {
    eprintln!("用法:");
    eprintln!("  dvd-hide embed    DIS_ISO  DATA_FILE  OUTPUT_IMAGE  [--offset N]");
    eprintln!("  dvd-hide extract  IMAGE_FILE  OUTPUT_DATA           [--offset N]");
    eprintln!("  dvd-hide capacity DIS_ISO                            [--offset N]");
}

fn parse_int(s: &str) -> i64 {
    s.parse().unwrap_or_else(|_| {
        eprintln!("错误: 无法解析整数: {s}");
        std::process::exit(2);
    })
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        return 2;
    }

    let cmd = args[1].as_str();
    let mut positionals: Vec<String> = Vec::new();
    let mut offset: i64 = 0;

    let mut i = 2;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--offset" {
            i += 1;
            if i >= args.len() {
                eprintln!("错误: --offset 需要一个整数");
                return 2;
            }
            offset = parse_int(&args[i]);
        } else if let Some(v) = a.strip_prefix("--offset=") {
            offset = parse_int(v);
        } else {
            positionals.push(a.to_string());
        }
        i += 1;
    }

    match cmd {
        "embed" => {
            if positionals.len() != 3 {
                usage();
                return 2;
            }
            let (dis, data, output) = (&positionals[0], &positionals[1], &positionals[2]);
            let data_bytes = match std::fs::read(data) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("错误: 读取数据文件失败: {e}");
                    return 1;
                }
            };
            match embed(dis, data_bytes, output, offset) {
                Ok((n, nb, nc)) => {
                    println!("完成: {dis} + {data} -> {output}");
                    println!("  数据 {n} 字节 → B {nb} 字节 → C {nc} 字节");
                }
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            }
        }
        "extract" => {
            if positionals.len() != 2 {
                usage();
                return 2;
            }
            match extract(&positionals[0], &positionals[1], offset) {
                Ok(n) => println!("完成: {} -> {}（{n} 字节）", positionals[0], positionals[1]),
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            }
        }
        "capacity" => {
            if positionals.len() != 1 {
                usage();
                return 2;
            }
            match capacity(&positionals[0], offset) {
                Ok((slots, total)) => {
                    let est = (slots as i128 * 64 / 65) - HEADER_LEN as i128;
                    println!(
                        "镜像: {}（{total} 字节，{} 扇区）",
                        positionals[0],
                        total / SECTOR as u64
                    );
                    println!("可用槽位（非 A5/92/9B 的字节数）: {slots}");
                    println!("预估可填充数据大小: 约 {est} 字节（{:.3} MiB）", est as f64 / 1048576.0);
                    println!("  （= 槽位 - 12 字节头 - 约 1/64 转义膨胀；实际取决于数据分布）");
                }
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            }
        }
        _ => {
            usage();
            return 2;
        }
    }
    0
}

fn main() {
    std::process::exit(run());
}
