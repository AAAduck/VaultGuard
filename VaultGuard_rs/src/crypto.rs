//! 密码学核心：HKDF/PBKDF2/Argon2id 派生 + 流式 AES-256-GCM（GHASH 用 RustCrypto ghash crate）。
//! 容器格式：
//!   VG\x03 —— 当前格式：用户口令 + Argon2id 派生（防拿到程序/源码的攻击者）；
//!   VG\x02 —— 内置密钥 + HKDF（防随手翻看，不防知道本工具的人）；
//!   VG\x01 —— 旧版（仅解密兼容）。
//! AAD 绑定格式版本与外壳类型，跨外壳改名会被认证拒绝。

use std::io;

use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, generic_array::GenericArray};
use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use ctr::cipher::StreamCipher;
use ctr::Ctr128BE;
use ghash::{universal_hash::UniversalHash, Block as GBlock, GHash as GHashCore};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

pub const FMT_V3: &[u8; 3] = b"VG\x03";
pub const FMT_V2: &[u8; 3] = b"VG\x02";
pub const FMT_V1: &[u8; 3] = b"VG\x01";
pub const FMT_ALL: [&[u8]; 3] = [FMT_V3, FMT_V2, FMT_V1];

pub const AAD_V3: &[u8] = b"VG\x03";
pub const AAD_V2: &[u8] = b"VG\x02";
pub const AAD_V1: &[u8] = b"VG\x01";

pub const SALT_SZ: usize = 32;
pub const NONCE_SZ: usize = 12;
pub const TAG_SZ: usize = 16;
pub const KDF_N: u32 = 600_000; // v1 PBKDF2 迭代

pub const SHELL_PNG: u8 = 0x00;
pub const SHELL_JPG: u8 = 0x01;
pub const SHELL_DOCX: u8 = 0x02;

// v3 KDF（Argon2id）参数（写入文件头，未来调整不影响旧文件解密）
pub const KDF_ARGON2ID: u8 = 0x01;
pub const ARGON_SALT_SZ: usize = 16;
pub const ARGON_M_KIB: u32 = 65_536; // 64 MiB
pub const ARGON_T: u32 = 3;
pub const ARGON_P: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgonParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for ArgonParams {
    fn default() -> Self {
        Self {
            m_kib: ARGON_M_KIB,
            t: ARGON_T,
            p: ARGON_P,
        }
    }
}

/// 固定主密钥（base64('lu765YZ5uOM8hPMdceQDcOEQeBnOGYaXHXzXkl6FrYY=')）。
/// 仅用于 VG\x01/\x02 旧格式与"无口令模式"；VG\x03 口令格式不经过此密钥。
pub const MASTER_KEY: [u8; 32] = {
    // 由 base64 字面量逐字解码得到，编译期常量
    let b = b"lu765YZ5uOM8hPMdceQDcOEQeBnOGYaXHXzXkl6FrYY=";
    let mut o = [0u8; 32];
    let mut oi = 0usize;
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        let v: u32 = if c >= b'A' && c <= b'Z' {
            (c - b'A') as u32
        } else if c >= b'a' && c <= b'z' {
            (c - b'a' + 26) as u32
        } else if c >= b'0' && c <= b'9' {
            (c - b'0' + 52) as u32
        } else if c == b'+' {
            62
        } else if c == b'/' {
            63
        } else {
            i += 1;
            continue;
        };
        i += 1;
        bits = bits << 6 | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            o[oi] = (bits >> nbits) as u8;
            oi += 1;
        }
    }
    o
};

pub fn derive_v2(salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), &MASTER_KEY);
    let mut okm = [0u8; 32];
    hk.expand(b"VaultGuard\x06", &mut okm)
        .expect("hkdf expand");
    okm
}

pub fn derive_v1(salt: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&MASTER_KEY, salt, KDF_N, &mut okm);
    okm
}

/// v3：Argon2id(口令, salt) -> 32 字节文件密钥。参数随文件头存储。
pub fn derive_v3(pass: &[u8], salt: &[u8], prm: ArgonParams) -> io::Result<[u8; 32]> {
    let params = Params::new(prm.m_kib, prm.t, prm.p, Some(32))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("KDF 参数无效: {e}")))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut okm = [0u8; 32];
    a.hash_password_into(pass, salt, &mut okm)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("密钥派生失败: {e}")))?;
    Ok(okm)
}

pub fn aad_for(fmt: &[u8; 3], shell: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(4);
    v.extend_from_slice(fmt);
    v.push(shell);
    v
}

// ── 流式 AES-256-GCM（CTR 键流 + ghash crate 计算认证标记）─────────
// 字节布局与标准 GCM 一致：S = GHASH_H(AAD || pad || C || pad || len64(A) || len64(C))，
// tag = S ^ E(K, J0+1)。分块喂入任意长度（内部缓冲补零到块边界）。

pub struct Gcm {
    ctr: Ctr128BE<Aes256>,
    ghash: GHashCore,
    enc_j0: [u8; 16],
    pend: [u8; 16],
    pend_len: usize,
    aad_done: bool,
    aad_len: u64,
    data_len: u64,
}

impl Gcm {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8]) -> Self {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut h = [0u8; 16];
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut h));
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        let mut enc_j0 = j0;
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut enc_j0));
        let mut g = Gcm {
            ctr: gcm_ctr(key, nonce),
            ghash: GHashCore::new(GBlock::from_slice(&h)),
            enc_j0,
            pend: [0u8; 16],
            pend_len: 0,
            aad_done: false,
            aad_len: 0,
            data_len: 0,
        };
        g.gadd(aad);
        g.aad_len = aad.len() as u64;
        g.aad_done = true;
        g.flush_pad(); // AAD -> 密文切换时按规范补零对齐
        g
    }

    /// 加密/解密一页（CTR 键流就地异或），随后需手动把密文喂给 ghash_data。
    pub fn crypt_in_place(&mut self, buf: &mut [u8]) {
        self.ctr.apply_keystream(buf);
    }

    /// 把密文累计进 GHASH。
    pub fn ghash_data(&mut self, c: &[u8]) {
        self.data_len += c.len() as u64;
        self.gadd(c);
    }

    fn gadd(&mut self, data: &[u8]) {
        let mut data = data;
        if self.pend_len > 0 {
            let need = 16 - self.pend_len;
            let take = need.min(data.len());
            self.pend[self.pend_len..self.pend_len + take]
                .copy_from_slice(&data[..take]);
            self.pend_len += take;
            data = &data[take..];
            if self.pend_len == 16 {
                let b = self.pend;
                self.ghash.update_padded(&b);
                self.pend_len = 0;
            }
        }
        let full = data.len() - data.len() % 16;
        if full > 0 {
            self.ghash.update_padded(&data[..full]);
        }
        let rem = &data[full..];
        if !rem.is_empty() {
            self.pend[..rem.len()].copy_from_slice(rem);
            self.pend_len = rem.len();
        }
    }

    /// 把未满块的残余按 GCM 规范补零吸收。
    fn flush_pad(&mut self) {
        if self.pend_len > 0 {
            let mut blk = [0u8; 16];
            blk[..self.pend_len].copy_from_slice(&self.pend[..self.pend_len]);
            self.ghash.update_padded(&blk);
            self.pend = [0u8; 16];
            self.pend_len = 0;
        }
    }

    /// 计算最终 tag（消耗自身）。解密侧与期望值比较必须用常量时间比较。
    pub fn finish_tag(mut self) -> [u8; 16] {
        self.flush_pad();
        let mut lb = [0u8; 16];
        lb[..8].copy_from_slice(&(self.aad_len.wrapping_mul(8)).to_be_bytes());
        lb[8..].copy_from_slice(&(self.data_len.wrapping_mul(8)).to_be_bytes());
        self.ghash.update_padded(&lb);
        let s = self.ghash.finalize();
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = s[i] ^ self.enc_j0[i];
        }
        tag
    }
}

/// 常量时间等值比较（认证标记校验用）。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn gcm_ctr(key: &[u8; 32], nonce: &[u8; 12]) -> Ctr128BE<Aes256> {
    let mut iv = [0u8; 16];
    iv[..12].copy_from_slice(nonce);
    iv[12..].copy_from_slice(&[0, 0, 0, 2]);
    let key_ga = GenericArray::from_slice(key);
    let iv_ga = GenericArray::from_slice(&iv);
    Ctr128BE::new(key_ga, iv_ga)
}
