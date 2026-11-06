//! DVD 主数据扰码 / 反扰码 —— ECMA-267 第 17 节（Rust 移植自 dvd_scramble.py）。
//!
//! 扰码是 Q = P ⊕ S，其中 S 是 15 位 LFSR 生成的掩码字节流。
//! 因为 XOR 是自逆的，本程序就是它自己的逆：
//!     扰码(加密)     : 输入 P → 输出 Q = P ⊕ S
//!     反扰码(解密)   : 输入 Q → 输出 P = Q ⊕ S
//!
//! 规则：
//!     文件按 2048 字节一个扇区处理；
//!     第 i 个扇区(0 起)落在盘上的 ECC block = offset + i//16；
//!     preset = block & 0xF → 生成该扇区 2048 字节掩码 S；Q[k] = P[k] ⊕ S[k]。
//!
//! 用法:
//!     dvd-scramble 输入 输出 [--offset BLOCK]

use std::fs::File;
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Write};

use dvd_tools::{SECTOR, masks, preset_index};

fn usage() {
    eprintln!("用法: dvd-scramble 输入 输出 [--offset BLOCK]");
    eprintln!("  --offset 是输入数据最终落在盘上的起始 ECC block 号，默认 0。");
}

fn parse_int(s: &str) -> i64 {
    s.parse().unwrap_or_else(|_| {
        eprintln!("错误: 无法解析整数: {s}");
        std::process::exit(2);
    })
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let mut positionals: Vec<String> = Vec::new();
    let mut offset: i64 = 0;

    let mut i = 1;
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

    if positionals.len() != 2 {
        usage();
        return 2;
    }
    let input = &positionals[0];
    let output = &positionals[1];

    let total_sectors = match std::fs::metadata(input) {
        Ok(m) => (m.len() as i64 + (SECTOR as i64 - 1)) / SECTOR as i64,
        Err(e) => {
            eprintln!("错误: 无法读取 {input}: {e}");
            return 1;
        }
    };
    let show = io::stderr().is_terminal();
    let masks = masks();

    let fin = match File::open(input) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("错误: 打开 {input} 失败: {e}");
            return 1;
        }
    };
    let mut fin = BufReader::new(fin);
    let fout = match File::create(output) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("错误: 创建 {output} 失败: {e}");
            return 1;
        }
    };
    let mut fout = BufWriter::new(fout);

    let mut buf = [0u8; SECTOR];
    let mut sector_index: i64 = 0;

    loop {
        let mut n = 0usize;
        while n < SECTOR {
            match fin.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(r) => n += r,
                Err(e) => {
                    eprintln!("错误: 读取失败: {e}");
                    return 1;
                }
            }
        }
        if n == 0 {
            break;
        }
        buf[n..].fill(0); // 末扇区补零

        let mask = &masks[preset_index(offset, sector_index)];
        for k in 0..SECTOR {
            buf[k] ^= mask[k];
        }
        if let Err(e) = fout.write_all(&buf) {
            eprintln!("错误: 写入失败: {e}");
            return 1;
        }

        sector_index += 1;
        if show && (sector_index % 500 == 0 || sector_index == total_sectors) {
            let pct = sector_index * 100 / total_sectors;
            eprint!("\r  扇区 {}/{} ({}%)", sector_index, total_sectors, pct);
            let _ = io::stderr().flush();
        }
    }

    if show {
        eprintln!();
    }

    println!(
        "处理了 {} 个扇区：{} -> {}（起始 block {}）",
        sector_index, input, output, offset
    );
    0
}

fn main() {
    std::process::exit(run());
}
