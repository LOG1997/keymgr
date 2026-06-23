use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::error::KeymgrError;
use crate::model::{MasterHash, Vault};

/// 获取数据目录路径：`$XDG_CONFIG_HOME/keymgr/data/`
pub fn data_dir() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("keymgr").join("data")
}

/// vault.json 路径
pub fn vault_path() -> PathBuf {
    data_dir().join("vault.json")
}

/// master.hash 路径
pub fn master_hash_path() -> PathBuf {
    data_dir().join("master.hash")
}

/// 确保数据目录存在。在 Unix 上同时设置目录权限为 0o700。
pub fn ensure_data_dir() -> Result<(), KeymgrError> {
    let dir = data_dir();
    fs::create_dir_all(&dir)?;
    set_dir_permissions(&dir)?;
    Ok(())
}

/// 读取 vault.json，若文件不存在则返回空 Vault。
pub fn read_vault() -> Result<Vault, KeymgrError> {
    let path = vault_path();
    if !path.exists() {
        return Ok(Vault::default());
    }
    let content = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&content)?)
}

/// 写入 vault.json。在 Unix 上同时设置文件权限为 0o600。
pub fn write_vault(vault: &Vault) -> Result<(), KeymgrError> {
    let path = vault_path();
    let content = serde_json::to_string_pretty(vault)?;

    let mut file = fs::File::create(&path)?;
    file.write_all(content.as_bytes())?;
    // drop file 以便后续 set_permissions 不会遇到共享冲突
    drop(file);

    set_file_permissions(&path)?;
    Ok(())
}

/// 读取 master.hash
pub fn read_master_hash() -> Result<MasterHash, KeymgrError> {
    let path = master_hash_path();
    if !path.exists() {
        return Err(KeymgrError::NotInitialized);
    }
    let content = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&content)?)
}

/// 写入 master.hash。在 Unix 上同时设置文件权限为 0o600。
pub fn write_master_hash(master: &MasterHash) -> Result<(), KeymgrError> {
    let path = master_hash_path();
    let content = serde_json::to_string_pretty(master)?;

    let mut file = fs::File::create(&path)?;
    file.write_all(content.as_bytes())?;
    drop(file);

    set_file_permissions(&path)?;
    Ok(())
}

/// 检查是否已初始化（master.hash 是否存在）
pub fn is_initialized() -> bool {
    master_hash_path().exists()
}

// ─── 平台特定的权限设置 ──────────────────────────

#[cfg(unix)]
fn set_dir_permissions(path: &std::path::Path) -> Result<(), KeymgrError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &std::path::Path) -> Result<(), KeymgrError> {
    // Windows 上不设置 POSIX 权限
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &std::path::Path) -> Result<(), KeymgrError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &std::path::Path) -> Result<(), KeymgrError> {
    // Windows 上不设置 POSIX 权限
    Ok(())
}
