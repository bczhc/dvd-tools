//! dvd-guard-runs：给 DVD 镜像插 guard 字节，打断读不出的 0x92 连段。
//!
//! 关键：guard 必须做在**扰码后的 Q 域**（EFM+ 实际看到的字节），不是 P 域（ISO 原始数据）。
//! 所以流程是：
//!   P ──⊕mask──▶ Q ──guard──▶ Q' ──⊕mask──▶ P'
//!
//! guard 做两件事：
//!   1. 把每个长度 >= --min 的连续 0x92 段的首字节替换成 0x9B（其余 0x92 不动）；
//!   2. 把所有扇区首字节（% 2048 == 0）置为 0x9B。
//!
//! 用法:
//!     dvd-guard-runs 输入 输出 [--min N]

use dvd_tools::{masks, SECTOR};

const RUN_BYTE: u8 = 0x92;
const GUARD: u8 = 0x9B;
const BLOCK_SECTORS: usize = 16;
const BLOCK_BYTES: usize = SECTOR * BLOCK_SECTORS; // 32768

fn usage() {
    eprintln!("用法: dvd-guard-runs 输入 输出 [--min N]");
    eprintln!("  --min N  连续 0x92 至少 N 个才替换其首字节（默认 16）");
}

fn parse_usize(s: &str) -> usize {
    s.parse().unwrap_or_else(|_| {
        eprintln!("错误: 无法解析整数: {s}");
        std::process::exit(2);
    })
}

/// 对整个镜像做扰码（XOR 掩码，自逆）。掩码以 512KiB 为周期，preset = block & 0xF。
fn scramble(data: &mut [u8]) {
    let m = masks();
    for (block_idx, chunk) in data.chunks_mut(BLOCK_BYTES).enumerate() {
        let mask = &m[block_idx & 0xF];
        for sector in chunk.chunks_mut(SECTOR) {
            for (b, &mb) in sector.iter_mut().zip(mask.iter()) {
                *b ^= mb;
            }
        }
    }
}

/// 把每个长度 >= min_run 的连续 0x92 段的首字节替换成 0x9B。返回替换次数。
fn guard_runs(data: &mut [u8], min_run: usize) -> usize {
    let mut replaced = 0;
    let mut i = 0;
    while i < data.len() {
        if data[i] == RUN_BYTE {
            let start = i;
            while i < data.len() && data[i] == RUN_BYTE {
                i += 1;
            }
            if i - start >= min_run {
                data[start] = GUARD;
                replaced += 1;
            }
        } else {
            i += 1;
        }
    }
    replaced
}

/// 把所有 % SECTOR == 0 的位置置为 0x9B。返回实际发生变化的次数。
fn guard_sectors(data: &mut [u8]) -> usize {
    let mut changed = 0;
    let mut i = 0;
    while i < data.len() {
        if data[i] != GUARD {
            data[i] = GUARD;
            changed += 1;
        }
        i += SECTOR;
    }
    changed
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let mut positionals: Vec<String> = Vec::new();
    let mut min_run = 16usize;

    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--min" {
            i += 1;
            if i >= args.len() {
                eprintln!("错误: --min 需要一个整数");
                return 2;
            }
            min_run = parse_usize(&args[i]);
        } else if let Some(v) = a.strip_prefix("--min=") {
            min_run = parse_usize(v);
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

    let mut data = match std::fs::read(input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("错误: 读取 {input} 失败: {e}");
            return 1;
        }
    };

    // P -> Q
    scramble(&mut data);

    let runs = guard_runs(&mut data, min_run);
    let sectors = guard_sectors(&mut data);

    // Q -> P
    scramble(&mut data);

    if let Err(e) = std::fs::write(output, &data) {
        eprintln!("错误: 写入 {output} 失败: {e}");
        return 1;
    }

    let total_sectors = data.len().div_ceil(SECTOR);
    println!("处理了 {total_sectors} 个扇区：{input} -> {output}");
    println!("  Q 域 0x92 连段首字节替换（长度 >= {min_run}）: {runs} 处");
    println!("  Q 域扇区首字节置 0x9B（实际变化）: {sectors} 处");
    0
}

fn main() {
    std::process::exit(run());
}
