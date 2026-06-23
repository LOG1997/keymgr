use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeymgrError {
    #[error("未初始化，请先运行 `keymgr init`")]
    NotInitialized,

    #[error("主密码验证失败")]
    MasterPasswordMismatch,

    #[error("密钥名称 '{0}' 已存在")]
    DuplicateKey(String),

    #[error("密钥 '{0}' 不存在")]
    KeyNotFound(String),

    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("序列化错误: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("加密/解密错误: {0}")]
    Crypto(String),

    #[error("密码输入错误: {0}")]
    PasswordInput(String),

    #[error("Base64 解码错误: {0}")]
    Base64(#[from] base64::DecodeError),
}
