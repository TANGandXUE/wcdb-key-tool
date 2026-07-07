# wcdb-key-tool

微信数据库（WCDB / SQLCipher4）密钥提取工具，覆盖 Linux / macOS / Windows 三个平台。

Extract WeChat (WCDB/SQLCipher4) database encryption keys — Linux, macOS and Windows.

本仓库只做一件事：把从微信自己的进程里，合法地取出**自己账号**数据库密钥这件事的
思路和代码公开出来，不做采集、不做批量、不接触任何服务器通信。

## 背景 / Background

微信 4.1+ 版本不再在进程内存中缓存明文数据库密钥（raw key），而是只保留一个
passphrase，真正的加密密钥需要再做一轮很慢的密码学运算才能算出来。这导致所有
基于内存模式扫描（`x'<hex>'`）的老工具全部失效。

WeChat 4.1+ no longer caches the raw database encryption key in process memory —
only a passphrase remains, from which the real key must be derived. This breaks
every existing tool that relies on `x'<hex>'` memory pattern scanning.

## 兼容性 / Compatibility

| 平台 | 微信 4.0.x（老版本） | 微信 4.1+（新版本） |
|------|---|---|
| Linux | ✅ 内存扫描 | ✅ GDB 断点 + PBKDF2 派生（已验证） |
| macOS | ✅ 内存扫描 | ✅ LLDB 断点 + PBKDF2 派生（已验证） |
| Windows | ✅ 内存扫描 | ⚠️ 实验性方案，**未经真机验证**（见下） |

- Linux: `wcdb_key_tool.py`
- macOS: `wcdb_key_tool_macos.py`
- Windows: `wcdb_key_tool_windows.py`

## 核心原理 / How It Works

三个平台最终都是同一套密码学逻辑，只是"怎么从微信进程里把原料弄出来"这一步不同：

1. **拿到密钥原料**（三条路线，按微信版本二选一）
   - 老版本：微信自己把 `raw key + salt` 拼成十六进制字符串，明文缓存在进程内存里，
     直接内存扫描就能拿到。
   - 新版本：内存里只剩 passphrase，拿不到直接能用的密钥，得走第 2 步。
   - 新版本的 passphrase 只在微信**登录时**做一次计算，之后就常驻内存不会重复计算，
     所以要抓这一刻，得用调试器在这次计算发生的地方下断点，逼用户退出登录再重新
     登录来触发一次新的计算，从函数参数寄存器里把 passphrase 读出来。
     - Linux：微信 Linux 二进制没有暴露可用的系统符号，只能用 ELF 静态分析（在
       `.rodata` 里找 WCDB 特征字符串，顺着交叉引用找到处理密钥的函数入口），
       再用 GDB 在这个地址上断点。（`elf_analyzer.py` + `gdb_capture.py`，已在
       真机验证）
     - macOS：微信直接调用了苹果系统自带的 `CommonCrypto` 库做密钥派生，这是一个
       公开的系统符号，不需要逆向微信自己的二进制，直接用 LLDB 断在
       `CCKeyDerivationPBKDF` 上就行。（`lldb_capture.py`，已在真机验证 18/18）
     - Windows：**未验证**。技术上合理的猜测是微信同样调用系统密码库
       （CNG 的 `BCryptDeriveKeyPBKDF2`），可以用 WinDbg 命令行版 `cdb.exe`
       断在这个系统函数上试试，但没有 Windows 微信环境实测过，随时可能因为
       假设不成立而抓不到任何东西。见 `wcdb_key_tool_windows.py` 里的
       `capture-experimental` 子命令和文件内详细注释。

2. **PBKDF2 派生每个库的真实密钥**：拿到 passphrase 后，对每个数据库文件，用它
   自己的 16 字节 salt 做 `PBKDF2-HMAC-SHA512`（256,000 轮迭代），算出这个库专属
   的 32 字节 AES-256 密钥。

3. **HMAC 校验**：派生出密钥后不能直接信，要用密钥对数据库第一页做
   `HMAC-SHA512` 校验，跟数据库自己存的 HMAC 对上了，才说明这把密钥真的对。
   这一步是三个平台通用的"防止抓错"的安全网，也是判断实验性方案有没有真的成功
   的唯一标准——断点命中了不代表读到的就是对的东西，HMAC 校验通过才算数。

4. **AES-256-CBC 逐页解密**：还原出标准 SQLite 文件。

## 安装 / Install

单文件即可运行，无需 pip install 任何第三方库（三个平台都是直接调用系统自带的
加密库：Linux 走 OpenSSL、macOS 走 CommonCrypto、Windows 走 CNG）。

```bash
# Linux
sudo apt install gdb

# macOS
xcode-select --install   # 提供 lldb

# Windows
# capture-experimental 需要 cdb.exe（Windows SDK 里的 "Debugging Tools for Windows" 组件）
# 老版本内存扫描本身不需要额外安装任何东西
```

## 使用 / Usage

```bash
# Linux
sudo python3 wcdb_key_tool.py extract --decrypt

# macOS（首次需要先对微信重签名去掉 Hardened Runtime，见脚本内 Prerequisite）
sudo codesign --force --deep --sign - /Applications/WeChat.app
sudo python3 wcdb_key_tool_macos.py extract --decrypt

# Windows（老版本微信）
python3 wcdb_key_tool_windows.py extract --decrypt

# Windows（新版本，实验性方案，未验证，愿意帮忙测试的可以试试）
python3 wcdb_key_tool_windows.py capture-experimental
```

首次提取都需要在微信里**退出登录再重新登录**一次（这是为了触发密钥的重新计算，
断点才有机会命中）；抓到的 passphrase 会缓存下来，之后就不用重复这一步了。

## Windows 新版：实验性方案说明

`wcdb_key_tool_windows.py` 里的 `capture-experimental` 是一个**有技术依据但完全
没有真机验证过**的方案：Linux 用 GDB、macOS 用 LLDB 的等价方案都已经在真实设备
上跑通过，Windows 这条目前只是"照着同样的思路猜一次"，没有人验证过微信 Windows
版是不是真的调用了假设中的那个系统函数，也没有验证过断点条件、寄存器读法、
输出解析格式对不对。

如果你有 Windows 微信环境愿意帮忙测试（不管测试结果是成功还是失败），欢迎提
Issue / PR，这是目前整个仓库唯一还没解决的缺口。

## 安全说明 / Security Notes

- 本工具只用于提取**用户自己设备上自己账号**的数据库密钥
- 调试器只在密钥计算的一瞬间附加、读一次寄存器/内存就立即 detach，不修改微信
  的任何行为，不接触网络协议
- 不会触发封号

## FAQ

**Q: 会不会封号？**
A: 不会。工具只在密钥计算瞬间读一次内存/寄存器值，整个过程很短，不修改任何程序
行为，不接触微信服务器通信。

**Q: passphrase 存在哪里？**
A: 存储在 `~/.wcdb-key-tool/wechat-passphrase.json`（权限 600），仅当前用户可读，
三个平台通用这一个路径。

**Q: 为什么 Linux/macOS 需要 sudo？**
A: GDB / LLDB 需要 `ptrace`（macOS 上是 `task_for_pid`）权限来附加到其他进程的
内存空间。Linux 也可以用 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`
临时放开权限（重启后恢复），不用每次都 sudo。

**Q: 微信更新后还能用吗？**
A: Linux 大概率可以——ELF 静态分析通过字符串交叉引用定位函数，只要微信继续使用
WCDB 的 `com.Tencent.WCDB.Config.Cipher` 字符串，就能自动适配。macOS 断的是苹果
系统函数，跟微信自己的版本无关，理论上更稳定，但微信升级后可能需要重新对 App
执行一次重签名（Hardened Runtime 被系统还原后 `task_for_pid` 会失败）。

## 致谢 / Credits

- [kkocdko](https://kkocdko.site/post/202510212134) — Linux 上 GDB 断点法的原始思路
- [wxchat-export](https://github.com/lopleec/wxchat-export) — Linux 上 ELF 静态分析方法
- [ylytdeng/wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt) — 内存扫描基础代码
- [TANGandXUE](https://github.com/TANGandXUE) — PBKDF2 派生方法 + macOS/Windows 移植 + 完整集成

## License

MIT — see [LICENSE](LICENSE)
