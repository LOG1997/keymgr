# keymgr

本地密钥管理终端工具 —— 用一把主密码安全地管理你的所有密钥（API Key、Token、密码等）。

| 使用codewhale(deepseek)完整生成

## 安全设计

- **AES-256-GCM** 加密存储，每条密钥使用独立的随机 nonce
- **Argon2id** 派生加密密钥，抗暴力破解
- **主密码不回显**，输入过程无屏幕残留
- 解密后的明文使用后**自动从内存擦除**（`zeroize`）
- 数据目录权限锁为 `700`，文件权限锁为 `600`
- `list` 命令**无需主密码**，以掩码形式预览密钥

## 安装

```bash
cargo install --path .
```

## 快速开始

```bash
# 1. 初始化（首次使用必须执行）
keymgr init

# 2. 添加密钥
keymgr add my-api-key

# 3. 查看所有密钥（掩码显示，无需主密码）
keymgr list

# 4. 查看密钥完整值（需验证主密码）
keymgr get my-api-key

# 5. 更新密钥
keymgr update my-api-key

# 6. 删除密钥
keymgr remove my-api-key

# 7. 修改主密码（重新加密所有密钥）
keymgr passwd
```

## 命令参考

| 命令 | 说明 | 需要主密码 |
|------|------|:-----------:|
| `keymgr init` | 初始化 keymgr，设置主密码 | — |
| `keymgr add <名称>` | 添加新密钥 | ✓ |
| `keymgr list` | 列出所有密钥（掩码显示） | ✗ |
| `keymgr get <名称>` | 查看密钥的完整明文值 | ✓ |
| `keymgr update <名称>` | 更新已有密钥的值 | ✓ |
| `keymgr remove <名称>` | 删除指定密钥 | ✓ |
| `keymgr passwd` | 修改主密码并重加密所有密钥 | ✓ |
| `keymgr --help` | 显示帮助 | — |
| `keymgr --version` | 显示版本 | — |

## 数据存储

所有数据存储在 `$XDG_CONFIG_HOME/keymgr/data/` 目录下（通常是 `~/.config/keymgr/data/`）：

- **`master.hash`** —— 主密码的 Argon2id 验证哈希与密钥派生盐值
- **`vault.json`** —— 所有密钥的加密仓库

## 掩码规则

`list` 命令以掩码形式展示密钥值，规则如下：

| 原始长度 | 掩码规则 | 示例 |
|---------|---------|------|
| > 8 | 保留首尾各 4 字符 | `my-secret-token` → `my-s***oken` |
| ≤ 8 | 隐藏一半长度 | `abcdefgh` → `ab****gh` |
| | | `abcd` → `a**d` |
| 1 | 完整显示 | `a` → `a` |

## 技术栈

- **Rust** (edition 2021)
- **clap** —— CLI 参数解析
- **aes-gcm** —— AES-256-GCM 加解密
- **argon2** —— Argon2id 密码哈希与密钥派生
- **zeroize** —— 敏感数据内存擦除
- **rpassword** —— 密码安全输入
- **serde / serde_json** —— 序列化

## 安全注意事项

- 主密码是唯一凭据，**丢失后无法恢复**所有密钥
- 建议定期使用 `keymgr passwd` 更换主密码
- 请勿将 `data/` 目录上传到公开仓库或非安全存储
- 当前版本仅支持单用户本地使用，不适合多用户共享场景
