//! dvd-tools 共享代码：ECMA-267 第 17 节 DVD 主数据扰码。
//!
//! 扰码是 XOR 自逆的：Q = P ⊕ S，其中 S 是 15 位 LFSR 生成的掩码字节流。
//! 这里只提供最底层的掩码生成原语；「哪个扇区用哪个掩码」的映射由各 bin 自行决定。

use std::sync::OnceLock;

/// DVD 一个主数据扇区的字节数。
pub const SECTOR: usize = 2048;

/// 一个扇区的扰码掩码。
pub type Mask = [u8; SECTOR];

/// ECMA-267 表 3 —— 16 个 LFSR 预置值，索引 = ECC block 号 & 0xF。
pub const PRESETS: [u16; 16] = [
    0x0001, 0x5500, 0x0002, 0x2A00,
    0x0004, 0x5400, 0x0008, 0x2800,
    0x0010, 0x5000, 0x0020, 0x2001,
    0x0040, 0x4002, 0x0080, 0x0005,
];

/// 15 位 LFSR 敲一个时钟：feedback = r14 ⊕ r10，左移，反馈进 r0。
#[inline(always)]
pub fn advance(state: u16) -> u16 {
    let fb = ((state >> 14) ^ (state >> 10)) & 1;
    ((state << 1) | fb) & 0x7FFF
}

/// 由一个 preset 下标（0..15）生成 2048 字节的扰码掩码。
pub fn build_mask(preset: u16) -> Mask {
    let mut state = PRESETS[(preset & 0xF) as usize];
    let mut mask = [0u8; SECTOR];
    for m in mask.iter_mut() {
        *m = (state & 0xFF) as u8; // 取低 8 位
        for _ in 0..8 {
            state = advance(state); // 一个字节 = 8 个时钟
        }
    }
    mask
}

/// 预计算并缓存的 16 个掩码，下标 = preset（0..15）。
#[inline]
pub fn masks() -> &'static [Mask; 16] {
    static MASKS: OnceLock<[Mask; 16]> = OnceLock::new();
    MASKS.get_or_init(|| std::array::from_fn(|p| build_mask(p as u16)))
}

/// 由「起始 ECC block 偏移 + 扇区号」得到 preset 下标（0..15）。
#[inline(always)]
pub fn preset_index(offset: i64, sector: i64) -> usize {
    ((offset + sector.div_euclid(16)) & 0xF) as usize
}
