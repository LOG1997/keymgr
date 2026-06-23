mod cli;
mod crypto;
mod error;
mod mask;
mod model;
mod store;

use std::io::{self, Write};

use chrono::{Local, TimeZone};
use clap::Parser;
use zeroize::Zeroize;

use crate::cli::{Cli, Command};
use crate::error::KeymgrError;
use crate::model::{KeyDisplay, KeyEntry, SecureString};

// ─── 入口 ───────────────────────────────────────

fn main() {
    if let Err(e) = run() {
        eprintln!("错误: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), KeymgrError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init => cmd_init()?,
        Command::Add { name } => cmd_add(&name)?,
        Command::List => cmd_list()?,
        Command::Get { name } => cmd_get(&name)?,
        Command::Update { name } => cmd_update(&name)?,
        Command::Remove { name } => cmd_remove(&name)?,
        Command::Passwd => cmd_passwd()?,
    }

    Ok(())
}

// ─── 工具函数 ──────────────────────────────────

/// 交互式输入密码（不回显），返回自动清零的 SecureString。
fn prompt_password(prompt: &str) -> Result<SecureString, KeymgrError> {
    let password =
        rpassword::prompt_password(prompt).map_err(|e| KeymgrError::PasswordInput(e.to_string()))?;
    Ok(SecureString::new(password))
}

/// 交互式输入主密码并验证，返回 DEK 和密码（密码用于后续可能的派生）。
fn verify_and_get_dek(master: &model::MasterHash) -> Result<(model::Dek, SecureString), KeymgrError> {
    let password = prompt_password("请输入主密码: ")?;
    if !crypto::verify_master_password(master, &password)? {
        return Err(KeymgrError::MasterPasswordMismatch);
    }
    let dek = crypto::derive_dek(master, &password)?;
    Ok((dek, password))
}

/// 将 Unix 时间戳格式化为 `YYYY-MM-DD HH:MM:SS`
fn format_timestamp(ts: i64) -> String {
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "未知时间".to_string())
}

// ─── 命令实现 ──────────────────────────────────

/// `keymgr init` —— 初始化，设置主密码。
fn cmd_init() -> Result<(), KeymgrError> {
    if store::is_initialized() {
        eprintln!(
            "keymgr 已经初始化。如需重新初始化，请删除 {} 后重试。",
            store::master_hash_path().display()
        );
        return Ok(());
    }

    eprintln!("首次使用，请设置主密码（字符不会回显）。");

    let password = prompt_password("请输入新主密码: ")?;
    let confirm = prompt_password("请再次输入新主密码: ")?;

    if password.as_ref() != confirm.as_ref() {
        return Err(KeymgrError::Crypto("两次输入的密码不一致".into()));
    }

    store::ensure_data_dir()?;

    let master = crypto::create_master_hash(&password)?;
    store::write_master_hash(&master)?;

    // 初始化空 vault
    store::write_vault(&model::Vault::default())?;

    println!("✓ keymgr 初始化成功！");
    eprintln!("  数据目录: {}", store::data_dir().display());

    Ok(())
}

/// `keymgr add <name>` —— 添加新密钥。
fn cmd_add(name: &str) -> Result<(), KeymgrError> {
    let master = store::read_master_hash()?;
    let (dek, _password) = verify_and_get_dek(&master)?;

    let mut vault = store::read_vault()?;

    // 检查重名
    if vault.entries.iter().any(|e| e.name == name) {
        return Err(KeymgrError::DuplicateKey(name.to_string()));
    }

    let secret = prompt_password(&format!("请输入密钥 '{}' 的值: ", name))?;
    let masked_preview = mask::mask_value(secret.as_ref());

    let (ciphertext, nonce) = crypto::encrypt(&dek, secret.as_ref())?;

    let now = Local::now().timestamp();

    vault.entries.push(KeyEntry {
        name: name.to_string(),
        ciphertext,
        nonce,
        masked_preview,
        created_at: now,
        updated_at: now,
    });

    store::write_vault(&vault)?;

    println!("✓ 密钥 '{}' 已添加。", name);

    Ok(())
}

/// `keymgr list` —— 列出所有密钥（掩码显示，无需主密码）。
fn cmd_list() -> Result<(), KeymgrError> {
    let vault = store::read_vault()?;

    if vault.entries.is_empty() {
        println!("(暂无密钥)");
        return Ok(());
    }

    // 按名称排序
    let mut entries: Vec<&KeyEntry> = vault.entries.iter().collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let displays: Vec<KeyDisplay> = entries
        .iter()
        .map(|e| KeyDisplay {
            name: e.name.clone(),
            masked_value: e.masked_preview.clone(),
            created_at: format_timestamp(e.created_at),
            updated_at: format_timestamp(e.updated_at),
        })
        .collect();

    // 简单输出格式
    let sep = "─".repeat(50);
    for (i, d) in displays.iter().enumerate() {
        if i > 0 {
            println!("{}", sep);
        }
        println!("名称:     {}", d.name);
        println!("掩码值:   {}", d.masked_value);
        println!("添加时间: {}", d.created_at);
        println!("更新时间: {}", d.updated_at);
    }

    Ok(())
}

/// `keymgr get <name>` —— 查看密钥完整值（需主密码验证）。
fn cmd_get(name: &str) -> Result<(), KeymgrError> {
    let master = store::read_master_hash()?;
    let (dek, _password) = verify_and_get_dek(&master)?;

    let vault = store::read_vault()?;
    let entry = vault
        .entries
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| KeymgrError::KeyNotFound(name.to_string()))?;

    let mut plaintext = crypto::decrypt(&dek, &entry.ciphertext, &entry.nonce)?;

    println!("{}", plaintext);

    // 打印后立即从内存中擦除
    plaintext.zeroize();

    Ok(())
}

/// `keymgr update <name>` —— 更新已有密钥的值。
fn cmd_update(name: &str) -> Result<(), KeymgrError> {
    let master = store::read_master_hash()?;
    let (dek, _password) = verify_and_get_dek(&master)?;

    let mut vault = store::read_vault()?;
    let entry = vault
        .entries
        .iter_mut()
        .find(|e| e.name == name)
        .ok_or_else(|| KeymgrError::KeyNotFound(name.to_string()))?;

    let new_secret = prompt_password(&format!("请输入密钥 '{}' 的新值: ", name))?;
    let masked_preview = mask::mask_value(new_secret.as_ref());

    let (ciphertext, nonce) = crypto::encrypt(&dek, new_secret.as_ref())?;

    entry.ciphertext = ciphertext;
    entry.nonce = nonce;
    entry.masked_preview = masked_preview;
    entry.updated_at = Local::now().timestamp();

    store::write_vault(&vault)?;

    println!("✓ 密钥 '{}' 已更新。", name);

    Ok(())
}

/// `keymgr remove <name>` —— 删除指定密钥。
fn cmd_remove(name: &str) -> Result<(), KeymgrError> {
    let master = store::read_master_hash()?;
    let (_dek, _password) = verify_and_get_dek(&master)?;

    let mut vault = store::read_vault()?;

    let idx = vault
        .entries
        .iter()
        .position(|e| e.name == name)
        .ok_or_else(|| KeymgrError::KeyNotFound(name.to_string()))?;

    // 确认
    eprint!("确认删除密钥 '{}'？[y/N]: ", name);
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() != "y" {
        println!("已取消。");
        return Ok(());
    }

    vault.entries.remove(idx);
    store::write_vault(&vault)?;

    println!("✓ 密钥 '{}' 已删除。", name);

    Ok(())
}

/// `keymgr passwd` —— 修改主密码（重加密所有密钥）。
fn cmd_passwd() -> Result<(), KeymgrError> {
    let master = store::read_master_hash()?;

    // 1. 验证旧密码
    let old_password = prompt_password("请输入旧主密码: ")?;
    if !crypto::verify_master_password(&master, &old_password)? {
        return Err(KeymgrError::MasterPasswordMismatch);
    }
    let old_dek = crypto::derive_dek(&master, &old_password)?;

    // 2. 输入新密码
    let new_password = prompt_password("请输入新主密码: ")?;
    let confirm = prompt_password("请再次输入新主密码: ")?;
    if new_password.as_ref() != confirm.as_ref() {
        return Err(KeymgrError::Crypto("两次输入的密码不一致".into()));
    }

    // 3. 创建新的 master hash
    let new_master = crypto::create_master_hash(&new_password)?;
    let new_dek = crypto::derive_dek(&new_master, &new_password)?;

    // 4. 逐个解密 → 重加密 → 清零
    let mut vault = store::read_vault()?;
    for entry in &mut vault.entries {
        // 用旧 DEK 解密
        let mut pt = crypto::decrypt(&old_dek, &entry.ciphertext, &entry.nonce)?;

        // 掩码不变（值未变），但重新计算以保持一致性
        let preview = mask::mask_value(&pt);

        // 用新 DEK 加密
        let (ciphertext, nonce) = crypto::encrypt(&new_dek, &pt)?;

        entry.ciphertext = ciphertext;
        entry.nonce = nonce;
        entry.masked_preview = preview;
        // updated_at 保持不变（密钥值未变，只是重加密）

        // 立即从内存中擦除明文
        pt.zeroize();
    }

    // 5. 写入
    store::write_master_hash(&new_master)?;
    store::write_vault(&vault)?;

    println!("✓ 主密码已更新，{} 条密钥已用新密码重新加密。", vault.entries.len());

    Ok(())
}
