use clap::{Parser, Subcommand};

/// 本地密钥管理终端工具
#[derive(Parser)]
#[command(name = "keymgr", about = "本地密钥管理终端工具", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// 初始化 keymgr，设置主密码（首次使用必须执行）
    Init,

    /// 添加新密钥
    Add {
        /// 密钥的唯一名称
        name: String,
    },

    /// 列出所有已存储的密钥（掩码显示）
    List,

    /// 查看指定密钥的完整值（需验证主密码）
    Get {
        /// 密钥名称
        name: String,
    },

    /// 更新已有密钥的值
    Update {
        /// 密钥名称
        name: String,
    },

    /// 删除指定密钥
    Remove {
        /// 密钥名称
        name: String,
    },

    /// 修改主密码（会重加密所有密钥）
    Passwd,
}
