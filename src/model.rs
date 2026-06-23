use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// 整个密钥仓库
#[derive(Serialize, Deserialize, Default)]
pub struct Vault {
    pub version: u32,
    pub entries: Vec<KeyEntry>,
}

/// 单条密钥记录
#[derive(Serialize, Deserialize)]
pub struct KeyEntry {
    /// 密钥唯一名称（明文存储）
    pub name: String,
    /// AES-256-GCM 加密后的密文（含 16 字节 tag）—— 以 base64 编码存储
    pub ciphertext: String,
    /// 加密时使用的 96-bit nonce —— 以 base64 编码存储
    pub nonce: String,
    /// 预计算的掩码预览（如 "abc***xyz"），用于 list 命令
    pub masked_preview: String,
    /// 创建时间（Unix 时间戳）
    pub created_at: i64,
    /// 最后更新时间（Unix 时间戳）
    pub updated_at: i64,
}

/// 主密码哈希文件
#[derive(Serialize, Deserialize)]
pub struct MasterHash {
    /// 验证盐（base64）
    pub verify_salt: String,
    /// 验证哈希（Argon2id PHC 编码字符串）
    pub verify_hash: String,
    /// 密钥派生盐（base64）
    pub dek_salt: String,
}

/// 用于 list 命令展示的条目
pub struct KeyDisplay {
    pub name: String,
    pub masked_value: String,
    pub created_at: String,
    pub updated_at: String,
}

/// 临时持有明文敏感数据，drop 时自动清零
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecureString(pub String);

impl SecureString {
    pub fn new(s: String) -> Self {
        SecureString(s)
    }
}

impl AsRef<str> for SecureString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// AES-256 密钥，drop 时自动清零
pub struct Dek(pub [u8; 32]);

impl Drop for Dek {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
