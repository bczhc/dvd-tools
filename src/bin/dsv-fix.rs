//! dsv-fix：DVD 图案镜像的 DSV 直流偏置修复。
//!
//! run --method 1|2|3  三种修复方法（都先扰码到 Q 域，塞 guard 后再扰码回 P 域）：
//!   1 = guard-runs：Q 域 0x92 连段首字节（>= --min）+ 扇区首字节塞 0x9B
//!   2 = guard-16：Q 域每隔 16 字节塞 0x9B（0xA5 除外）
//!   3 = bridge：原始方法（扇区首字节 + 0x92 run 首字节，密度启发式）

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rayon::prelude::*;

use dvd_tools::{SECTOR, masks};

// ==================== DVD 扰码（ECMA-267 第17节） ====================
const BLOCK_SECTORS: usize = 16;
const BLOCK: usize = SECTOR * BLOCK_SECTORS; // 32768
const PERIOD: usize = BLOCK * 16; // 524288 = 512KiB
const CHUNK: usize = 8 * 1024 * 1024; // 8MiB

fn build_period() -> Vec<u8> {
    let mut v = Vec::with_capacity(PERIOD);
    for m in masks() {
        for _ in 0..BLOCK_SECTORS {
            v.extend_from_slice(m);
        }
    }
    v
}

fn build_chunk_mask(period: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(CHUNK);
    while v.len() < CHUNK {
        let take = (CHUNK - v.len()).min(period.len());
        v.extend_from_slice(&period[..take]);
    }
    v
}

// ==================== 方法 1/2：guard-runs / guard-16 ====================
const RUN_BYTE: u8 = 0x92;
const GUARD: u8 = 0x9B;
const BLACK: u8 = 0xA5;
const GUARD16_STEP: usize = 16;

/// 整盘扰码（XOR 掩码，自逆）。掩码以 512KiB 为周期，preset = block & 0xF。
fn scramble(data: &mut [u8]) {
    let m = masks();
    for (block_idx, chunk) in data.chunks_mut(BLOCK).enumerate() {
        let mask = &m[block_idx & 0xF];
        for sector in chunk.chunks_mut(SECTOR) {
            for (b, &mb) in sector.iter_mut().zip(mask.iter()) {
                *b ^= mb;
            }
        }
    }
}

/// 方法1：把每个长度 >= min_run 的连续 0x92 段的首字节替换成 0x9B。
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

/// 方法1：把所有扇区首字节（% 2048 == 0）置为 0x9B。
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

/// 方法2：每隔 16 字节塞 0x9B（0xA5 除外）。
fn guard_every16(data: &mut [u8]) -> usize {
    let mut changed = 0;
    for i in (0..data.len()).step_by(GUARD16_STEP) {
        if data[i] != BLACK {
            if data[i] != GUARD {
                changed += 1;
            }
            data[i] = GUARD;
        }
    }
    changed
}

// ==================== bridge ====================
fn bridge_run(rec: &mut [u8], guard: u8, window: usize, min_pattern: f64) -> usize {
    let n = rec.len();
    let mut pattern = vec![0u32; n + 1];
    for i in 0..n {
        pattern[i + 1] = pattern[i] + u32::from(rec[i] == 0x92 || rec[i] == 0xA5);
    }
    let mut guards: Vec<usize> = Vec::new();
    for s in 0..(n / SECTOR) {
        guards.push(s * SECTOR);
    }
    let mut i = 0;
    while i < n {
        if rec[i] == 0x92 {
            let start = i;
            while i < n && rec[i] == 0x92 {
                i += 1;
            }
            let end = i;
            if end - start >= 2 {
                let ahead = if start + window <= n {
                    (pattern[start + window] - pattern[start]) as f64 / window as f64
                } else {
                    0.0
                };
                let behind = if start + 1 >= window {
                    (pattern[start + 1] - pattern[start + 1 - window]) as f64 / window as f64
                } else {
                    0.0
                };
                if ahead.max(behind) >= min_pattern {
                    guards.push(start);
                }
            }
        } else {
            i += 1;
        }
    }
    guards.sort_unstable();
    guards.dedup();
    let mut changed = 0;
    for g in guards {
        if rec[g] != guard {
            rec[g] = guard;
            changed += 1;
        }
    }
    changed
}

fn process_chunk(chunk: &mut [u8], mask: &[u8], guard: u8, window: usize, min_pattern: f64) -> usize {
    let m = &mask[..chunk.len()];
    for i in 0..chunk.len() {
        chunk[i] ^= m[i];
    }
    let changed = bridge_run(chunk, guard, window, min_pattern);
    for i in 0..chunk.len() {
        chunk[i] ^= m[i];
    }
    changed
}

// ==================== CLI ====================
#[derive(Parser)]
#[command(name = "dsv-fix", version, about = "DVD 图案镜像 DSV 修复")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 修复 DSV：--method 1=guard-runs 2=guard-16 3=bridge(原始)
    Run {
        input: PathBuf,
        output: PathBuf,
        /// 修复方法：1=guard-runs 2=guard-16 3=bridge
        #[arg(long, default_value_t = 1)]
        method: u8,
        /// 方法1：连续 0x92 至少 N 个才替换其首字节
        #[arg(long, default_value_t = 16)]
        min: usize,
        /// 方法3：guard 字节
        #[arg(long, default_value = "9B")]
        guard: String,
        #[arg(long, default_value_t = 64)]
        window: usize,
        #[arg(long, default_value_t = 0.9)]
        min_pattern: f64,
        #[arg(long, default_value_t = 0)]
        jobs: usize,
    },
}

fn main() {
    match Cli::parse().command {
        Command::Run { input, output, method, min, guard, window, min_pattern, jobs } => {
            run_fix(&input, &output, method, min, &guard, window, min_pattern, jobs);
        }
    }
}

/// 启动进度条线程，返回 join handle。
fn spawn_progress(total: usize, done: &Arc<AtomicUsize>) -> Option<std::thread::JoinHandle<()>> {
    if !std::io::stderr().is_terminal() {
        return None;
    }
    let done = Arc::clone(done);
    Some(std::thread::spawn(move || {
        loop {
            let d = done.load(Ordering::Relaxed);
            if d >= total {
                break;
            }
            eprint!("\r  处理中 {d}/{total} ({}%)", d * 100 / total.max(1));
            std::io::stderr().flush().ok();
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }))
}

fn run_fix(input: &PathBuf, output: &PathBuf, method: u8, min: usize, guard: &str, window: usize, min_pattern: f64, jobs: usize) {
    match method {
        1 => run_guard_runs(input, output, min),
        2 => run_guard_every16(input, output),
        3 => run_bridge(input, output, guard, window, min_pattern, jobs),
        _ => {
            eprintln!("错误: --method 只能是 1/2/3");
            std::process::exit(2);
        }
    }
}

fn run_guard_runs(input: &PathBuf, output: &PathBuf, min_run: usize) {
    let mut data = std::fs::read(input).expect("读入失败");
    scramble(&mut data);
    let runs = guard_runs(&mut data, min_run);
    let sectors = guard_sectors(&mut data);
    scramble(&mut data);
    std::fs::write(output, &data).expect("写出失败");
    let total_sectors = data.len().div_ceil(SECTOR);
    println!("处理了 {total_sectors} 个扇区：{} -> {}", input.display(), output.display());
    println!("  Q 域 0x92 连段首字节替换（长度 >= {min_run}）: {runs} 处");
    println!("  Q 域扇区首字节置 0x9B: {sectors} 处");
}

fn run_guard_every16(input: &PathBuf, output: &PathBuf) {
    let mut data = std::fs::read(input).expect("读入失败");
    scramble(&mut data);
    let changed = guard_every16(&mut data);
    scramble(&mut data);
    std::fs::write(output, &data).expect("写出失败");
    println!("处理了 {} 字节：{} -> {}", data.len(), input.display(), output.display());
    println!("  Q 域每隔 16 字节塞 0x9B（0xA5 除外）: {changed} 处");
}

fn run_bridge(input: &PathBuf, output: &PathBuf, guard: &str, window: usize, min_pattern: f64, jobs: usize) {
    let guard = u8::from_str_radix(guard.trim_start_matches("0x"), 16).expect("无效 guard");
    if output.exists() {
        eprintln!("{} 已存在，不覆盖", output.display());
        std::process::exit(2);
    }
    let mut data = std::fs::read(input).expect("读入失败");
    if data.len() % SECTOR != 0 {
        eprintln!("输入不是 2048 字节扇区的整数倍");
        std::process::exit(2);
    }
    let total_sectors = data.len() / SECTOR;
    let period = build_period();
    let chunk_mask = build_chunk_mask(&period);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(if jobs > 0 { jobs } else { 0 })
        .build()
        .expect("建线程池");

    let total = (data.len() + CHUNK - 1) / CHUNK;
    let done = Arc::new(AtomicUsize::new(0));
    let progress = spawn_progress(total, &done);

    let changed = pool.install(|| {
        data.par_chunks_mut(CHUNK)
            .map(|c| {
                let r = process_chunk(c, &chunk_mask, guard, window, min_pattern);
                done.fetch_add(1, Ordering::Relaxed);
                r
            })
            .sum::<usize>()
    });

    if let Some(h) = progress {
        h.join().ok();
    }
    if std::io::stderr().is_terminal() {
        eprintln!();
    }

    std::fs::write(output, &data).expect("写出失败");
    println!(
        "{total_sectors} sectors; {changed} bytes changed ({:.2} % of the image), guard {guard:02X}",
        changed as f64 * 100.0 / data.len() as f64
    );
}
