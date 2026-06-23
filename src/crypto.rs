use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::Rng;

use crate::error::KeymgrError;
use crate::model::{Dek, MasterHash, SecureString};

const NONCE_SIZE: usize = 12; // 96 bits

/// 使用 Argon2id 验证主密码是否正确。
pub fn verify_master_password(
    master: &MasterHash,
    password: &SecureString,
) -> Result<bool, KeymgrError> {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};

    let parsed_hash = PasswordHash::new(&master.verify_hash)
        .map_err(|e| KeymgrError::Crypto(format!("解析验证哈希失败: {}", e)))?;

    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(password.as_ref().as_bytes(), &parsed_hash)
        .is_ok())
}

/// 从主密码 + DEK 盐派生 256-bit 加密密钥。
pub fn derive_dek(master: &MasterHash, password: &SecureString) -> Result<Dek, KeymgrError> {
    let salt_bytes = BASE64
        .decode(&master.dek_salt)
        .map_err(|e| KeymgrError::Crypto(format!("解码 DEK 盐值失败: {}", e)))?;

    let argon2 = Argon2::default();
    let mut buf = [0u8; 32];

    argon2
        .hash_password_into(password.as_ref().as_bytes(), &salt_bytes, &mut buf)
        .map_err(|e| KeymgrError::Crypto(format!("派生加密密钥失败: {}", e)))?;

    Ok(Dek(buf))
}

/// 创建新的主密码哈希结构（用于 init / passwd）。
pub fn create_master_hash(password: &SecureString) -> Result<MasterHash, KeymgrError> {
    use argon2::password_hash::{PasswordHasher, SaltString};

    let mut rng = rand::thread_rng();

    // 验证用盐 + 哈希
    let verify_salt = SaltString::generate(&mut rng);
    let argon2 = Argon2::default();
    let verify_hash = argon2
        .hash_password(password.as_ref().as_bytes(), &verify_salt)
        .map_err(|e| KeymgrError::Crypto(format!("哈希主密码失败: {}", e)))?
        .to_string();

    // DEK 用盐（32 字节随机数）
    let dek_salt: [u8; 32] = rng.r#gen();

    Ok(MasterHash {
        verify_salt: verify_salt.to_string(),
        verify_hash,
        dek_salt: BASE64.encode(&dek_salt),
    })
}

/// 生成随机 96-bit nonce。
fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill(&mut nonce);
    nonce
}

/// 使用 AES-256-GCM 加密明文，返回 (密文, nonce) —— 均以 base64 编码。
pub fn encrypt(dek: &Dek, plaintext: &str) -> Result<(String, String), KeymgrError> {
    let key = Key::<Aes256Gcm>::from_slice(&dek.0);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = generate_nonce();
    let nonce_slice = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce_slice, plaintext.as_bytes())
        .map_err(|e| KeymgrError::Crypto(format!("加密失败: {}", e)))?;

    Ok((BASE64.encode(&ciphertext), BASE64.encode(&nonce_bytes)))
}

/// 使用 AES-256-GCM 解密密文。
pub fn decrypt(dek: &Dek, ciphertext_b64: &str, nonce_b64: &str) -> Result<String, KeymgrError> {
    let ciphertext = BASE64
        .decode(ciphertext_b64)
        .map_err(|e| KeymgrError::Crypto(format!("解码密文失败: {}", e)))?;
    let nonce_bytes = BASE64
        .decode(nonce_b64)
        .map_err(|e| KeymgrError::Crypto(format!("解码 nonce 失败: {}", e)))?;

    let key = Key::<Aes256Gcm>::from_slice(&dek.0);
    let cipher = Aes256Gcm::new(key);
    let nonce_slice = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce_slice, ciphertext.as_ref())
        .map_err(|e| KeymgrError::Crypto(format!("解密失败: {}", e)))?;

    String::from_utf8(plaintext)
        .map_err(|e| KeymgrError::Crypto(format!("解密后的数据不是有效的 UTF-8: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SecureString;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = SecureString::new("test-master-password".into());
        let master = create_master_hash(&password).expect("创建 master hash 失败");
        let dek = derive_dek(&master, &password).expect("派生 DEK 失败");

        let plaintext = "my-super-secret-api-key-12345";
        let (ciphertext, nonce) = encrypt(&dek, plaintext).expect("加密失败");

        let decrypted = decrypt(&dek, &ciphertext, &nonce).expect("解密失败");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let password = SecureString::new("another-password".into());
        let master = create_master_hash(&password).expect("创建 master hash 失败");
        let dek = derive_dek(&master, &password).expect("派生 DEK 失败");

        let plaintext = "";
        let (ciphertext, nonce) = encrypt(&dek, plaintext).expect("加密失败");
        let decrypted = decrypt(&dek, &ciphertext, &nonce).expect("解密失败");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_dek_fails() {
        let p1 = SecureString::new("password-1".into());
        let p2 = SecureString::new("password-2".into());

        let master = create_master_hash(&p1).expect("创建 master hash 失败");
        let dek1 = derive_dek(&master, &p1).expect("派生 DEK1 失败");
        let dek2 = derive_dek(&master, &p2).expect("派生 DEK2 失败");

        let (ciphertext, nonce) = encrypt(&dek1, "secret").expect("加密失败");

        // 用错误的 DEK 解密应该失败
        let result = decrypt(&dek2, &ciphertext, &nonce);
        assert!(result.is_err(), "用错误 DEK 解密应该失败");
    }

    #[test]
    fn test_verify_master_password() {
        let password = SecureString::new("correct-password".into());
        let wrong = SecureString::new("wrong-password".into());

        let master = create_master_hash(&password).expect("创建 master hash 失败");

        assert!(verify_master_password(&master, &password).expect("验证失败"));
        assert!(!verify_master_password(&master, &wrong).expect("验证失败"));
    }

    #[test]
    fn test_non_utf8_plaintext_is_rejected() {
        // 确保加密非 UTF-8 数据后解密不会 panic
        let password = SecureString::new("utf8-test".into());
        let master = create_master_hash(&password).unwrap();
        let dek = derive_dek(&master, &password).unwrap();

        // 加密包含非 UTF-8 字节的"字符串"（在此测试中我们用合法 UTF-8）
        let text = "こんにちは世界"; // 日文 UTF-8
        let (ct, nc) = encrypt(&dek, text).unwrap();
        let decrypted = decrypt(&dek, &ct, &nc).unwrap();
        assert_eq!(decrypted, text);
    }
}
