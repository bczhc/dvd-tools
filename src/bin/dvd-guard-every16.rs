//! dvd-guard-every16：Q 域里每隔 16 字节塞一个 0x9B（0xA5 除外），打断 DSV 自环。
//!
//! 做法：P ──⊕mask──▶ Q ──每 16 字节塞 0x9B──▶ Q' ──⊕mask──▶ P'
//! 0xA5（黑）保留不动，其余位置（% 16 == 0）都换成 0x9B。
//!
//! 用法:
//!     dvd-guard-every16 输入 输出

use dvd_tools::{masks, SECTOR};

const GUARD: u8 = 0x9B;
const BLACK: u8 = 0xA5; // 黑色保留
const STEP: usize = 16; // 每隔 16 字节
const BLOCK_BYTES: usize = SECTOR * 16;

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

fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("用法: dvd-guard-every16 输入 输出");
        return 2;
    }
    let input = &args[1];
    let output = &args[2];

    let mut data = match std::fs::read(input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("错误: 读取 {input} 失败: {e}");
            return 1;
        }
    };

    // P -> Q
    scramble(&mut data);

    // 每隔 16 字节，非 0xA5 就置 0x9B
    let mut changed = 0;
    for i in (0..data.len()).step_by(STEP) {
        if data[i] != BLACK {
            if data[i] != GUARD {
                changed += 1;
            }
            data[i] = GUARD;
        }
    }

    // Q -> P
    scramble(&mut data);

    if let Err(e) = std::fs::write(output, &data) {
        eprintln!("错误: 写入 {output} 失败: {e}");
        return 1;
    }

    println!("处理了 {} 字节：{input} -> {output}", data.len());
    println!("  每隔 {STEP} 字节塞 0x9B（0xA5 除外）: {changed} 处");
    0
}

fn main() {
    std::process::exit(run());
}
