//! dsv-balancer：DVD 图案镜像的 DSV 平衡 + 整盘 DSV 检查。
//!
//! run    把镜像过一遍，消除杀手字节（每扇区首字节 + 每 0x92 run 首字节塞 guard）
//! check  对整盘每个 ECC block 计算峰值 |DSV|（含头/EDC/ECC/EFM+），找出仍超阈值的块
//!
//! DSV 计算是 dsv_block.py 的忠实移植（ECMA-267：扰码 + Reed-Solomon PI/PO + EDC +
//! EFM+ 带 DSV 控制），与 Python 输出一致。

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rayon::prelude::*;

use dvd_tools::{SECTOR, masks};

include!("../tables.rs");

// ==================== DVD 扰码（ECMA-267 第17节） ====================
const BLOCK_SECTORS: usize = 16;
const BLOCK: usize = SECTOR * BLOCK_SECTORS; // 32768
const PERIOD: usize = BLOCK * 16; // 524288 = 512KiB
const CHUNK: usize = 8 * 1024 * 1024; // 8MiB
const DATA_START_PSN: u32 = 0x30000;

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

// ==================== GF(256) + Reed-Solomon ====================
struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf256 {
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11D;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Gf256 { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }
}

fn rs_generator(gf: &Gf256, n: usize) -> Vec<u8> {
    let mut g = vec![1u8];
    for k in 0..n {
        let mut out = vec![0u8; g.len() + 1];
        for (i, &c) in g.iter().enumerate() {
            out[i] ^= c;
            if c != 0 {
                out[i + 1] ^= gf.exp[gf.log[c as usize] as usize + k];
            }
        }
        g = out;
    }
    g
}

fn rs_parity(gf: &Gf256, data: &[u8], g: &[u8]) -> Vec<u8> {
    let n = g.len() - 1;
    let mut reg = vec![0u8; n];
    for &d in data {
        let fb = d ^ reg[0];
        reg.rotate_left(1);
        reg[n - 1] = 0;
        if fb != 0 {
            let lfb = gf.log[fb as usize] as usize;
            for i in 0..n {
                reg[i] ^= gf.exp[gf.log[g[i + 1] as usize] as usize + lfb];
            }
        }
    }
    reg
}

// ==================== EDC（CRC-32，ECMA-267） ====================
fn edc(data: &[u8]) -> u32 {
    let mut reg: u32 = 0;
    for &byte in data {
        for k in (0..8).rev() {
            let top = (reg >> 31) & 1;
            reg = ((reg << 1) & 0xFFFF_FFFF) | ((byte as u32 >> k) & 1);
            if top != 0 {
                reg ^= 0x8000_0011;
            }
        }
    }
    for _ in 0..32 {
        let top = (reg >> 31) & 1;
        reg = (reg << 1) & 0xFFFF_FFFF;
        if top != 0 {
            reg ^= 0x8000_0011;
        }
    }
    reg
}

// ==================== EFM+（ECMA-267 第20/22节，带 DSV 控制） ====================
#[derive(Clone)]
struct Boundary {
    state: u8,
    dsv: i32,
    land: bool,
}

impl Boundary {
    fn new() -> Self {
        Boundary { state: 1, dsv: 0, land: true }
    }
}

#[derive(Clone)]
struct Stream {
    words: Vec<u16>,
    state: u8,
    dsv: i32,
    land: bool,
    primary: bool,
    zeros: i32,
}

impl Stream {
    fn new(b: &Boundary, sync: u32, primary: bool) -> Self {
        let mut s = Stream {
            words: Vec::with_capacity(93),
            state: b.state,
            dsv: b.dsv,
            land: b.land,
            primary,
            zeros: 0,
        };
        s.put_word((sync >> 16) as u16);
        s.put_word(sync as u16);
        s.state = 1; // 每个 SYNC 码都以 1 结尾
        s
    }

    fn copy_from(&mut self, o: &Stream) {
        self.words.clone_from(&o.words);
        self.state = o.state;
        self.dsv = o.dsv;
        self.land = o.land;
        self.primary = o.primary;
        self.zeros = o.zeros;
    }

    fn put_word(&mut self, word: u16) {
        self.words.push(word);
        for k in (0..16).rev() {
            let t = (word >> k) & 1;
            if t == 1 {
                self.land = !self.land;
                self.zeros = 0;
            } else {
                self.zeros += 1;
            }
            self.dsv += if self.land { 1 } else { -1 };
        }
    }

    fn can(&self, word: u16) -> bool {
        let combined = self.zeros + word.leading_zeros() as i32;
        (2..=10).contains(&combined)
    }

    fn append(&mut self, wn: (u16, u8)) {
        debug_assert!(self.can(wn.0), "EFMPlus word would violate RLL(2,10)");
        self.put_word(wn.0);
        self.state = wn.1;
    }
}

fn main_word(v: u8, s: u8) -> (u16, u8) {
    let i = v as usize * 4 + s as usize - 1;
    (MAIN_WORDS[i], MAIN_NEXT[i])
}

fn sub_word(v: u8, s: u8) -> (u16, u8) {
    let i = v as usize * 4 + s as usize - 1;
    (SUB_WORDS[i], SUB_NEXT[i])
}

fn sync_word(state: u8, category: usize, primary: bool) -> u32 {
    SYNC[if state <= 2 { 0 } else { 1 }][if primary { 0 } else { 1 }][category]
}

/// 把 |dsv| 更小的流复制到另一条，返回公共 state。
fn select_copy(s1: &mut Stream, s2: &mut Stream) -> u8 {
    if s1.dsv.abs() <= s2.dsv.abs() {
        let sel = s1.clone();
        s2.copy_from(&sel);
        sel.state
    } else {
        let sel = s2.clone();
        s1.copy_from(&sel);
        sel.state
    }
}

fn two_reps(v: u8, s: &Stream) -> bool {
    (s.state == 1 || s.state == 4)
        && s.can(main_word(v, 1).0)
        && s.can(main_word(v, 4).0)
}

fn replay(words: &[u16], b: &Boundary) -> (Vec<u8>, i32, bool) {
    let mut level = Vec::with_capacity(words.len() * 16);
    let mut cur = b.land;
    let mut sum = 0i32;
    for &w in words {
        for k in (0..16).rev() {
            let t = (w >> k) & 1;
            if t == 1 {
                cur = !cur;
            }
            let lv = if cur { 1u8 } else { 0u8 };
            level.push(lv);
            sum += lv as i32;
        }
    }
    let dsv = b.dsv + 2 * sum - level.len() as i32;
    let land = level.last().copied().unwrap_or(0) == 1;
    (level, dsv, land)
}

/// 编码一个 91 字节 sync frame，返回 1488 个 channel level（1=land）和结束边界。
fn encode_frame(data: &[u8], category: usize, b: &Boundary) -> (Vec<u8>, Boundary) {
    debug_assert_eq!(data.len(), 91);
    let mut s1 = Stream::new(b, sync_word(b.state, category, true), true);
    let mut s2 = Stream::new(b, sync_word(b.state, category, false), false);

    for &value in data {
        let v = value;
        if value <= 87 {
            let st = select_copy(&mut s1, &mut s2);
            let (mw, mn) = main_word(v, st);
            let (sw, sn) = sub_word(v, st);
            s1.append((mw, mn));
            s2.append((sw, sn));
            continue;
        }
        let c1 = two_reps(v, &s1);
        let c2 = two_reps(v, &s2);
        if c1 && c2 {
            let _ = select_copy(&mut s1, &mut s2);
            s1.append(main_word(v, 1));
            s2.append(main_word(v, 4));
        } else if c1 || c2 {
            let use_el = if c1 {
                s1.dsv.abs() <= s2.dsv.abs()
            } else {
                s2.dsv.abs() < s1.dsv.abs()
            };
            if use_el {
                let sel = if c1 { s1.clone() } else { s2.clone() };
                s1.copy_from(&sel);
                s2.copy_from(&sel);
                s1.append(main_word(v, 1));
                s2.append(main_word(v, 4));
            } else {
                s1.append(main_word(v, s1.state));
                s2.append(main_word(v, s2.state));
            }
        } else {
            s1.append(main_word(v, s1.state));
            s2.append(main_word(v, s2.state));
        }
    }

    let win = if s1.dsv.abs() <= s2.dsv.abs() { &s1 } else { &s2 };
    let mut words = win.words.clone();
    if !(-64..=63).contains(&win.dsv) {
        let w = sync_word(b.state, category, !win.primary);
        let mut alt = words.clone();
        alt[0] = (w >> 16) as u16;
        alt[1] = w as u16;
        let (_, alt_dsv, _) = replay(&alt, b);
        if alt_dsv.abs() < win.dsv.abs() {
            words = alt;
        }
    }
    let (level, dsv, land) = replay(&words, b);
    (level, Boundary { state: win.state, dsv, land })
}

// ==================== recording rows + peak DSV ====================
fn recording_rows(payload: &[u8], lba: u32, gf: &Gf256) -> Vec<[u8; 182]> {
    let g_pi = rs_generator(gf, 10);
    let g_po = rs_generator(gf, 16);
    let g_ied = rs_generator(gf, 2);

    // 192 行 × 172 字节的数据区
    let mut data = vec![0u8; 192 * 172];
    for s in 0..16usize {
        let psn = lba + s as u32 + DATA_START_PSN;
        let ident = [0x00, (psn >> 16) as u8, (psn >> 8) as u8, psn as u8];
        let ied = rs_parity(gf, &ident, &g_ied);
        let mut head = Vec::with_capacity(12);
        head.extend_from_slice(&ident);
        head.extend_from_slice(&ied);
        head.extend_from_slice(&[0u8; 6]);

        let main = &payload[s * SECTOR..(s + 1) * SECTOR];
        // 扰码（Q = P ^ mask）
        let mask = &masks()[(((lba + s as u32 + DATA_START_PSN) >> 4) & 0xF) as usize];
        // EDC 是对未扰码的 head+main 算的（ECMA-267）
        let mut crc_input = Vec::with_capacity(2060);
        crc_input.extend_from_slice(&head);
        crc_input.extend_from_slice(main);
        let crc = edc(&crc_input);

        let mut frame = Vec::with_capacity(2064);
        frame.extend_from_slice(&head);
        for i in 0..SECTOR {
            frame.push(main[i] ^ mask[i]);
        }
        frame.push((crc >> 24) as u8);
        frame.push((crc >> 16) as u8);
        frame.push((crc >> 8) as u8);
        frame.push(crc as u8);

        data[s * 2064..(s + 1) * 2064].copy_from_slice(&frame);
    }

    // PO：172 列，每列 16 字节
    let mut full = vec![0u8; 208 * 172];
    full[..192 * 172].copy_from_slice(&data);
    for c in 0..172 {
        let col: Vec<u8> = (0..192).map(|r| data[r * 172 + c]).collect();
        let po = rs_parity(gf, &col, &g_po);
        for (i, &b) in po.iter().enumerate() {
            full[(192 + i) * 172 + c] = b;
        }
    }

    // PI：每行 10 字节
    let mut rows = vec![[0u8; 182]; 208];
    for r in 0..208 {
        rows[r][..172].copy_from_slice(&full[r * 172..(r + 1) * 172]);
        let pi = rs_parity(gf, &full[r * 172..(r + 1) * 172], &g_pi);
        rows[r][172..].copy_from_slice(&pi);
    }

    // 交织：每扇区 12 数据行 + 1 PO 行
    let mut order = Vec::with_capacity(208);
    for s in 0..16usize {
        order.extend(12 * s..12 * (s + 1));
        order.push(192 + s);
    }
    order.into_iter().map(|i| rows[i]).collect()
}

fn peak_dsv(payload: &[u8], lba: u32, gf: &Gf256) -> i32 {
    let rows = recording_rows(payload, lba, gf);
    let mut b = Boundary::new();
    let mut peak = 0i32;
    for (i, row) in rows.iter().enumerate() {
        let cats = ROW_SYNC[i % 13];
        for half in 0..2 {
            let cat = if half == 0 { cats.0 } else { cats.1 };
            let (level, nb) = encode_frame(&row[91 * half..91 * (half + 1)], cat, &b);
            let mut run = b.dsv;
            let mut mx = 0i32;
            for &lv in &level {
                run += if lv == 1 { 1 } else { -1 };
                mx = mx.max(run.abs());
            }
            peak = peak.max(mx);
            b = nb;
        }
    }
    peak
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
#[command(name = "dsv-balancer", version, about = "DVD 图案镜像 DSV 平衡与检查")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 平衡 DSV：每扇区首字节 + 每个 0x92 run 首字节塞 guard
    Run {
        input: PathBuf,
        output: PathBuf,
        #[arg(long, default_value = "9B")]
        guard: String,
        #[arg(long, default_value_t = 64)]
        window: usize,
        #[arg(long, default_value_t = 0.9)]
        min_pattern: f64,
        #[arg(long, default_value_t = 0)]
        jobs: usize,
    },
    /// 整盘每个 ECC block 计算峰值 |DSV|
    Check {
        input: PathBuf,
        #[arg(long, default_value_t = 100)]
        threshold: i64,
        /// 只检查前 N 个 block（0 = 全部）
        #[arg(long, default_value_t = 0)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        jobs: usize,
    },
}

fn main() {
    match Cli::parse().command {
        Command::Run { input, output, guard, window, min_pattern, jobs } => {
            run_bridge(&input, &output, &guard, window, min_pattern, jobs);
        }
        Command::Check { input, threshold, limit, jobs } => {
            run_check(&input, threshold, limit, jobs);
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

fn run_check(input: &PathBuf, threshold: i64, limit: usize, jobs: usize) {
    let data = std::fs::read(input).expect("读入失败");
    if data.len() % BLOCK != 0 {
        eprintln!("输入不是 32768 字节块(1 ECC block)的整数倍");
        std::process::exit(2);
    }
    let mut n_blocks = data.len() / BLOCK;
    if limit > 0 {
        n_blocks = n_blocks.min(limit);
    }
    let gf = Gf256::new();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(if jobs > 0 { jobs } else { 0 })
        .build()
        .expect("建线程池");

    let done = Arc::new(AtomicUsize::new(0));
    let progress = spawn_progress(n_blocks, &done);

    let results: Vec<(usize, i32)> = pool.install(|| {
        (0..n_blocks)
            .into_par_iter()
            .map(|b| {
                let lba = (b * BLOCK_SECTORS) as u32;
                let payload = &data[b * BLOCK..(b + 1) * BLOCK];
                let r = (b, peak_dsv(payload, lba, &gf));
                done.fetch_add(1, Ordering::Relaxed);
                r
            })
            .collect()
    });

    if let Some(h) = progress {
        h.join().ok();
    }
    if std::io::stderr().is_terminal() {
        eprintln!();
    }

    let mut over = 0usize;
    let mut worst = 0i32;
    let mut worst_block = 0usize;
    for (b, peak) in &results {
        if *peak > worst {
            worst = *peak;
            worst_block = *b;
        }
        if *peak > threshold as i32 {
            over += 1;
            println!("block {b} (LBA {}): {peak}", b * BLOCK_SECTORS);
        }
    }
    println!(
        "检查 {n_blocks} 块：{over} 块峰值 |DSV| > {threshold}，最大 {worst}（block {worst_block}）"
    );
}
