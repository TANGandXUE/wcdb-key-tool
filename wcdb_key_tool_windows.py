#!/usr/bin/env python3
"""wcdb-key-tool (Windows) — 微信数据库密钥提取工具

Windows 微信数据库密钥提取工具。完整支持仍在进程内存里缓存明文 raw key
的微信版本（4.0.x 一代）。微信 4.1+ 改为只缓存 passphrase 后，本仓库额外
提供一个**实验性、未经真机验证**的断点捕获方案（见下方 EXPERIMENTAL 段落
和 `capture-experimental` 子命令），原理上模仿 Linux 版 GDB / macOS 版
LLDB 的断点法，但从未在真实 Windows + 微信环境里跑通过，请勿当作已解决
的方案使用。

Usage:
    python3 wcdb_key_tool_windows.py extract              # 提取密钥（内存扫描，老版本微信）
    python3 wcdb_key_tool_windows.py capture-experimental  # [实验性/未验证] 断点抓 passphrase
    python3 wcdb_key_tool_windows.py set-passphrase <64位hex>  # 手动填入已获取的 passphrase
    python3 wcdb_key_tool_windows.py decrypt               # 解密数据库
    python3 wcdb_key_tool_windows.py extract --decrypt     # 提取 + 解密一步完成

Requirements:
    - Python 3.10+（Windows 自带 bcrypt.dll，无需第三方加密库）
    - 建议以管理员身份运行（读取其他进程内存需要足够权限）
    - capture-experimental 需要 cdb.exe（"Debugging Tools for Windows"，
      Windows SDK 的可选组件，或随 WinDbg 安装）

Known Gap:
    微信 4.1+ 在 Windows 上同样只缓存 passphrase，等价于 Linux 的 GDB
    断点法 / macOS 的 LLDB 断点法在 Windows 上还没有被任何人验证过。
    下方 EXPERIMENTAL 段落是一个有技术依据但完全未验证的猜测，需要一台
    真实的 Windows 微信环境去验证断点会不会命中、读出来的东西对不对。
    如果你验证过（不管成功还是失败），欢迎提 Issue/PR 反馈。

https://github.com/TANGandXUE/wcdb-key-tool
"""
from __future__ import annotations

import argparse
import ctypes
import glob
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import sys
import time

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

_print = lambda *a, **kw: print(*a, flush=True, **kw)  # noqa: E731

# ============================================================
# Constants
# ============================================================
PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80  # IV(16) + HMAC(64)
SQLITE_HDR = b"SQLite format 3\x00"

PASSPHRASE_FILE = os.path.join(os.path.expanduser("~"), ".wcdb-key-tool", "wechat-passphrase.json")


# ============================================================
# AES-CBC via Windows CNG (bcrypt.dll，系统自带，无需第三方依赖)
# ============================================================

if sys.platform == "win32":
    import ctypes.wintypes as wt

    _bcrypt = ctypes.WinDLL("bcrypt")
    _bcrypt.BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(wt.HANDLE), ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
    _bcrypt.BCryptSetProperty.argtypes = [wt.HANDLE, ctypes.c_wchar_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong]
    _bcrypt.BCryptGenerateSymmetricKey.argtypes = [
        wt.HANDLE, ctypes.POINTER(wt.HANDLE), ctypes.c_char_p, ctypes.c_ulong,
        ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong,
    ]
    _bcrypt.BCryptDecrypt.argtypes = [
        wt.HANDLE, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong,
    ]


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-256-CBC 解密（无 padding），走 CNG 的 bcrypt.dll。"""
    h_alg = wt.HANDLE()
    status = _bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(h_alg), "AES", None, 0)
    if status != 0:
        raise RuntimeError(f"BCryptOpenAlgorithmProvider failed: {status:#x}")
    try:
        mode = ("ChainingModeCBC\x00").encode("utf-16-le")
        status = _bcrypt.BCryptSetProperty(h_alg, "ChainingMode", mode, len(mode), 0)
        if status != 0:
            raise RuntimeError(f"BCryptSetProperty failed: {status:#x}")

        h_key = wt.HANDLE()
        status = _bcrypt.BCryptGenerateSymmetricKey(h_alg, ctypes.byref(h_key), None, 0, key, len(key), 0)
        if status != 0:
            raise RuntimeError(f"BCryptGenerateSymmetricKey failed: {status:#x}")
        try:
            iv_buf = ctypes.create_string_buffer(iv, len(iv))
            out_buf = ctypes.create_string_buffer(len(data))
            result_len = ctypes.c_ulong(0)
            status = _bcrypt.BCryptDecrypt(
                h_key, data, len(data), None,
                iv_buf, len(iv),
                out_buf, len(out_buf), ctypes.byref(result_len), 0,
            )
            if status != 0:
                raise RuntimeError(f"BCryptDecrypt failed: {status:#x}")
            return out_buf.raw[: result_len.value]
        finally:
            _bcrypt.BCryptDestroyKey(h_key)
    finally:
        _bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


# ============================================================
# HMAC Verification（与 SQLCipher4 规范一致，跨平台通用）
# ============================================================

def verify_enc_key(enc_key: bytes, db_page1: bytes) -> bool:
    salt = db_page1[:SALT_SZ]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)
    hmac_data = db_page1[SALT_SZ: PAGE_SZ - 80 + 16]
    stored_hmac = db_page1[PAGE_SZ - 64: PAGE_SZ]
    hm = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hm.digest() == stored_hmac


# ============================================================
# DB File Collection
# ============================================================

def collect_db_files(db_dir: str) -> tuple[list, dict]:
    db_files: list = []
    salt_to_dbs: dict[str, list[str]] = {}
    for root, _dirs, files in os.walk(db_dir):
        for name in files:
            if not name.endswith(".db") or name.endswith("-wal") or name.endswith("-shm"):
                continue
            path = os.path.join(root, name)
            size = os.path.getsize(path)
            if size < PAGE_SZ:
                continue
            with open(path, "rb") as f:
                page1 = f.read(PAGE_SZ)
            rel = os.path.relpath(path, db_dir)
            salt = page1[:SALT_SZ].hex()
            db_files.append((rel, path, size, salt, page1))
            salt_to_dbs.setdefault(salt, []).append(rel)
    return db_files, salt_to_dbs


# ============================================================
# 内存扫描（微信 4.0.x：raw key 仍以明文缓存在进程内存 —— 目前 Windows 唯一可用方案）
# ============================================================

_HEX_RE = re.compile(rb"x'([0-9a-fA-F]{64,192})'")


def _get_pids_windows() -> list[tuple[int, int]]:
    r = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    pids: list[tuple[int, int]] = []
    for line in r.stdout.strip().split("\n"):
        if not line.strip():
            continue
        p = line.strip('"').split('","')
        if len(p) >= 5:
            pid = int(p[1])
            mem = int(p[4].replace(",", "").replace(" K", "").strip() or "0")
            pids.append((pid, mem))
    if not pids:
        raise RuntimeError("Weixin.exe 未运行")
    pids.sort(key=lambda x: x[1], reverse=True)
    for pid, mem in pids:
        _print(f"[+] Weixin.exe PID={pid} ({mem // 1024}MB)")
    return pids


def _scan_memory_raw_key(db_dir: str, keys_file: str) -> dict:
    """扫描 Weixin.exe 进程内存，匹配 x'<64hex_enc_key><32hex_salt>' 明文密钥模式。"""
    db_files, salt_to_dbs = collect_db_files(db_dir)
    if not db_files:
        raise RuntimeError(f"在 {db_dir} 未找到可解密的 .db 文件")
    _print(f"找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的 salt")

    kernel32 = ctypes.windll.kernel32
    MEM_COMMIT = 0x1000
    READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}

    class MBI(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
            ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
            ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
            ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
        ]

    def read_mem(h, addr, sz):
        buf = ctypes.create_string_buffer(sz)
        n = ctypes.c_size_t(0)
        if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, sz, ctypes.byref(n)):
            return buf.raw[: n.value]
        return None

    def enum_regions(h):
        regs = []
        addr = 0
        mbi = MBI()
        while addr < 0x7FFFFFFFFFFF:
            if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                break
            if mbi.State == MEM_COMMIT and mbi.Protect in READABLE and 0 < mbi.RegionSize < 500 * 1024 * 1024:
                regs.append((mbi.BaseAddress, mbi.RegionSize))
            nxt = mbi.BaseAddress + mbi.RegionSize
            if nxt <= addr:
                break
            addr = nxt
        return regs

    pids = _get_pids_windows()
    key_map: dict[str, str] = {}
    remaining_salts = set(salt_to_dbs.keys())
    t0 = time.time()

    for pid, mem_kb in pids:
        h = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not h:
            _print(f"[WARN] 无法打开进程 PID={pid}，跳过（尝试以管理员身份运行）")
            continue
        try:
            for base, size in enum_regions(h):
                if not remaining_salts:
                    break
                data = read_mem(h, base, size)
                if not data:
                    continue
                for m in _HEX_RE.finditer(data):
                    hex_str = m.group(1).decode()
                    if len(hex_str) < 96:
                        continue
                    enc_key_hex, salt_hex = hex_str[:64], hex_str[64:96]
                    if salt_hex not in remaining_salts:
                        continue
                    enc_key = bytes.fromhex(enc_key_hex)
                    for rel, _path, _sz, s, page1 in db_files:
                        if s == salt_hex and verify_enc_key(enc_key, page1):
                            key_map[salt_hex] = enc_key_hex
                            remaining_salts.discard(salt_hex)
                            _print(f"  [FOUND] salt={salt_hex} enc_key={enc_key_hex}")
                            break
        finally:
            kernel32.CloseHandle(h)
        if not remaining_salts:
            break

    _print(f"\n扫描完成: {time.time() - t0:.1f}s, {len(pids)} 个进程")
    if not key_map:
        raise RuntimeError(
            "未能从进程内存提取到密钥。若微信已是 4.1+ 版本，raw key 不再缓存在内存中，"
            "内存扫描本身就找不到东西——可以试试 capture-experimental（未验证，见文件头说明）。"
        )
    _save_results(db_files, salt_to_dbs, key_map, db_dir, keys_file)
    return key_map


# ============================================================
# [EXPERIMENTAL / 未验证] CNG 断点捕获 passphrase（微信 4.1+ 猜想方案）
# ============================================================
#
# ⚠️ 警告：以下代码从未在真实 Windows + 微信环境里跑通过，纯粹是技术推理，
# 请不要当作已解决的方案使用，也不要在文档/宣传里说 Windows 新版已攻克。
#
# 推理依据：
# Linux 版 WCDB 的 PBKDF2 是自己实现/静态链接的，找不到系统导出符号，
# 只能靠 ELF 静态分析定位 WCDB 内部函数断点（见 elf_analyzer.py）。
# macOS 版 WCDB 则直接调用系统 CommonCrypto 的 CCKeyDerivationPBKDF——
# 一个系统自带、有公开符号的导出函数，不需要逆向微信自己的二进制
# （见 wcdb_key_tool_macos.py 里的 capture_passphrase_lldb）。
# 如果 Windows 版 WCDB 同样选择调用系统密码库而非自己实现，最接近的
# 系统函数是 CNG（Cryptography API: Next Generation）的
# BCryptDeriveKeyPBKDF2，导出自系统自带的 bcrypt.dll。
#
# 如果这个假设成立：用 WinDbg 的命令行版 cdb.exe attach 微信进程，在
# bcrypt!BCryptDeriveKeyPBKDF2 上下条件断点。x64 调用约定
# （BCryptDeriveKeyPBKDF2(hPrf, pbPassword, cbPassword, pbSalt, ...)）下，
# 第 2 个参数 pbPassword 在 RDX，第 3 个参数 cbPassword 在 R8；只在
# R8==32（32 字节 passphrase）时触发，命中后用 `db` 命令读 32 字节。
#
# 需要一台真实 Windows 微信环境验证的开放问题（欢迎提 Issue/PR 反馈）：
#   1. 微信 Windows 版是否真的调用 BCryptDeriveKeyPBKDF2——也可能走的是
#      旧版 CryptoAPI（CryptDeriveKey）、或者跟 Linux 一样自己实现/静态
#      链接了 PBKDF2，那样这个断点永远不会命中
#   2. 断点条件 r8==32 是否会命中大量无关调用（系统里其他地方也可能用
#      同一个函数派生 32 字节密钥），需不需要加其他过滤条件
#   3. attach 微信主进程是否需要管理员权限、是否会被反调试机制拦截
#   4. 下面 _parse_db_output() 解析 cdb.exe `db` 命令输出的正则，没有
#      真实输出样本校对过，格式很可能对不上，需要用真实输出调整

DEFAULT_CDB_TIMEOUT = 180


class ExperimentalCaptureError(RuntimeError):
    pass


def check_cdb_prerequisites() -> list[str]:
    issues = []
    if not shutil.which("cdb"):
        issues.append(
            "未检测到 cdb.exe，请安装 \"Debugging Tools for Windows\""
            "（Windows SDK 的可选组件，或随 WinDbg 安装）"
        )
    return issues


def _find_wechat_pid_windows() -> int | None:
    r = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    for line in r.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.strip('"').split('","')
        if len(parts) >= 2:
            return int(parts[1])
    return None


def _parse_db_output(text: str) -> str | None:
    """从 cdb.exe `db` 命令的输出中解析 32 字节 passphrase。

    WinDbg `db` 典型输出形如（未经真实样本核对，格式可能有出入）：
        00007ff6`12345678  8c fc 66 8a 1b 2c 3d 4e-5f 60 71 82 93 a4 b5 c6  ................
    """
    hex_bytes: list[str] = []
    for line in text.splitlines():
        m = re.match(r"^[0-9a-f`]+\s+((?:[0-9a-f]{2}[\s\-]+){15}[0-9a-f]{2})\s", line, re.IGNORECASE)
        if m:
            hex_bytes += re.findall(r"[0-9a-f]{2}", m.group(1))
    return "".join(hex_bytes[:32]).lower() if len(hex_bytes) >= 32 else None


def capture_passphrase_experimental(pid: int | None = None, timeout: int = DEFAULT_CDB_TIMEOUT) -> str:
    """[实验性/未验证] attach 微信进程，猜测性地断在 bcrypt!BCryptDeriveKeyPBKDF2 上。

    需要用户在捕获期间于微信内退出登录、重新登录来触发断点（如果这个
    猜测成立的话）。没有真机验证过，随时可能因为假设不成立而永远等不到命中。
    """
    issues = check_cdb_prerequisites()
    if issues:
        raise ExperimentalCaptureError("; ".join(issues))

    if pid is None:
        pid = _find_wechat_pid_windows()
    if not pid:
        raise ExperimentalCaptureError("未找到微信进程，请先启动并登录微信")

    _print("=" * 60)
    _print("  [实验性/未验证] 尝试断点捕获 passphrase")
    _print("  这条路从未在真机上验证过，可能永远等不到命中")
    _print("=" * 60)

    bp_action = (
        '.if (@r8 = 0n32) '
        '{ .echo WCDB_PASSPHRASE_BEGIN; db @rdx L20; .echo WCDB_PASSPHRASE_END } '
        '.else { g }'
    )
    cdb_cmd = f'bp bcrypt!BCryptDeriveKeyPBKDF2 "{bp_action}"; g'

    proc = subprocess.Popen(
        ["cdb", "-p", str(pid), "-c", cdb_cmd],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    buf = ""
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.2)
                continue
            buf += line
            if "WCDB_PASSPHRASE_END" in buf:
                break
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    if "WCDB_PASSPHRASE_BEGIN" not in buf:
        raise ExperimentalCaptureError(
            "超时未命中断点。可能是本猜测方案的假设不成立（微信没有调用"
            "BCryptDeriveKeyPBKDF2），也可能只是没有在捕获期间重新登录微信。"
        )

    segment = buf.split("WCDB_PASSPHRASE_BEGIN", 1)[1].split("WCDB_PASSPHRASE_END", 1)[0]
    ph = _parse_db_output(segment)
    if not ph:
        raise ExperimentalCaptureError(
            "断点命中了，但没能从 cdb.exe 输出里解析出 32 字节数据——"
            "大概率是 _parse_db_output() 的正则没对上真实输出格式，需要用真实样本调整。"
            f"\n原始输出片段：\n{segment[:500]}"
        )
    logger.info("[实验性] 断点命中并解析出 32 字节数据，但尚未验证这就是真正的 passphrase")
    return ph


# ============================================================
# PBKDF2 Key Derivation（拿到 passphrase 后走这条路，三平台通用）
# ============================================================

def _derive_keys_from_passphrase(passphrase: bytes, db_files: list, salt_to_dbs: dict) -> dict:
    key_map: dict[str, str] = {}
    total = len(salt_to_dbs)
    for i, salt_hex in enumerate(salt_to_dbs):
        salt = bytes.fromhex(salt_hex)
        enc_key = hashlib.pbkdf2_hmac("sha512", passphrase, salt, 256000, dklen=KEY_SZ)
        for _rel, _path, _sz, s, page1 in db_files:
            if s == salt_hex and verify_enc_key(enc_key, page1):
                key_map[salt_hex] = enc_key.hex()
                break
        if (i + 1) % 5 == 0 or i == total - 1:
            _print(f"  PBKDF2 派生: {i + 1}/{total} ({len(key_map)} 验证通过)")
    return key_map


def load_passphrase() -> str | None:
    try:
        with open(PASSPHRASE_FILE, "r") as f:
            return json.load(f).get("passphrase")
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return None


def save_passphrase(passphrase: str) -> None:
    os.makedirs(os.path.dirname(PASSPHRASE_FILE), exist_ok=True)
    with open(PASSPHRASE_FILE, "w") as f:
        json.dump({"passphrase": passphrase}, f, indent=2)
    os.chmod(PASSPHRASE_FILE, 0o600)
    logger.info(f"passphrase 已保存到 {PASSPHRASE_FILE}")


# ============================================================
# Key helpers
# ============================================================

def _strip_key_metadata(keys: dict) -> dict:
    return {k: v for k, v in keys.items() if not k.startswith("_")}


def _key_path_variants(rel_path: str) -> list[str]:
    normalized = rel_path.replace("\\", "/")
    variants: list[str] = []
    for candidate in (rel_path, normalized, normalized.replace("/", "\\"), normalized.replace("/", os.sep)):
        if candidate not in variants:
            variants.append(candidate)
    return variants


def _get_key_info(keys: dict, rel_path: str) -> dict | None:
    if ".." in rel_path.replace("\\", "/").split("/"):
        return None
    for candidate in _key_path_variants(rel_path):
        if candidate in keys and not candidate.startswith("_"):
            return keys[candidate]
    return None


def _save_results(db_files: list, salt_to_dbs: dict, key_map: dict, db_dir: str, out_file: str) -> None:
    _print(f"\n{'=' * 60}")
    _print(f"结果: {len(key_map)}/{len(salt_to_dbs)} salts 找到密钥")

    result: dict = {}
    for rel, _path, sz, salt_hex, _page1 in db_files:
        if salt_hex in key_map:
            result[rel] = {"enc_key": key_map[salt_hex], "salt": salt_hex, "size_mb": round(sz / 1024 / 1024, 1)}
            _print(f"  OK: {rel} ({sz / 1024 / 1024:.1f}MB)")
        else:
            _print(f"  MISSING: {rel} (salt={salt_hex})")

    if not result:
        raise RuntimeError("未能提取到任何密钥")

    result["_db_dir"] = db_dir
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    _print(f"\n密钥保存到: {out_file}")


# ============================================================
# Config Detection（读微信本地 ini 配置定位数据目录）
# ============================================================

def auto_detect_db_dir() -> str | None:
    """读取 %APPDATA%\\Tencent\\xwechat\\config\\*.ini 找到数据根目录，
    再匹配 xwechat_files\\*\\db_storage。"""
    appdata = os.environ.get("APPDATA", "")
    config_dir = os.path.join(appdata, "Tencent", "xwechat", "config")
    if not os.path.isdir(config_dir):
        return None

    data_roots: list[str] = []
    for ini_file in glob.glob(os.path.join(config_dir, "*.ini")):
        content = None
        for enc in ("utf-8", "gbk"):
            try:
                with open(ini_file, "r", encoding=enc) as f:
                    content = f.read(1024).strip()
                break
            except UnicodeDecodeError:
                continue
        if content and os.path.isdir(content):
            data_roots.append(content)

    candidates: list[str] = []
    for root in data_roots:
        for match in glob.glob(os.path.join(root, "xwechat_files", "*", "db_storage")):
            if os.path.isdir(match) and match not in candidates:
                candidates.append(match)

    return candidates[0] if candidates else None


# ============================================================
# Database Decryption
# ============================================================

def _decrypt_page(enc_key: bytes, page_data: bytes, pgno: int) -> bytes:
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    if pgno == 1:
        encrypted = page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ]
        decrypted = aes_cbc_decrypt(enc_key, iv, encrypted)
        return bytes(SQLITE_HDR + decrypted + b"\x00" * RESERVE_SZ)
    else:
        encrypted = page_data[: PAGE_SZ - RESERVE_SZ]
        decrypted = aes_cbc_decrypt(enc_key, iv, encrypted)
        return decrypted + b"\x00" * RESERVE_SZ


def _decrypt_database(db_path: str, out_path: str, enc_key: bytes) -> bool:
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ
    if file_size % PAGE_SZ != 0:
        _print(f"  [WARN] 文件大小 {file_size} 不是 {PAGE_SZ} 的倍数")
        total_pages += 1

    with open(db_path, "rb") as fin:
        page1 = fin.read(PAGE_SZ)
    if len(page1) < PAGE_SZ:
        _print("  [ERROR] 文件太小")
        return False

    salt = page1[:SALT_SZ]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)
    p1_hmac_data = page1[SALT_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    p1_stored_hmac = page1[PAGE_SZ - HMAC_SZ: PAGE_SZ]
    hm = hmac_mod.new(mac_key, p1_hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    if hm.digest() != p1_stored_hmac:
        _print(f"  [ERROR] Page 1 HMAC 验证失败! salt: {salt.hex()}")
        return False

    _print(f"  HMAC OK, {total_pages} pages")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)

    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b"\x00" * (PAGE_SZ - len(page))
                else:
                    break
            fout.write(_decrypt_page(enc_key, page, pgno))
            if pgno % 10000 == 0:
                _print(f"  进度: {pgno}/{total_pages} ({100 * pgno / total_pages:.1f}%)")

    return True


def decrypt_all(db_dir: str, out_dir: str, keys_file: str) -> dict:
    _print("=" * 60)
    _print("  WeChat 数据库解密器 (Windows)")
    _print("=" * 60)

    if not os.path.exists(keys_file):
        _print(f"[ERROR] 密钥文件不存在: {keys_file}")
        _print("请先运行: python3 wcdb_key_tool_windows.py extract")
        sys.exit(1)

    with open(keys_file, encoding="utf-8") as f:
        keys = _strip_key_metadata(json.load(f))
    _print(f"\n加载 {len(keys)} 个数据库密钥")
    os.makedirs(out_dir, exist_ok=True)

    db_files: list[tuple[str, str, int]] = []
    for root, _dirs, files in os.walk(db_dir):
        for fname in files:
            if fname.endswith(".db") and not fname.endswith("-wal") and not fname.endswith("-shm"):
                path = os.path.join(root, fname)
                rel = os.path.relpath(path, db_dir)
                db_files.append((rel, path, os.path.getsize(path)))
    db_files.sort(key=lambda x: x[2])
    _print(f"找到 {len(db_files)} 个数据库文件\n")

    success = failed = 0
    total_bytes = 0
    for rel, path, sz in db_files:
        key_info = _get_key_info(keys, rel)
        if not key_info:
            _print(f"SKIP: {rel} (无密钥)")
            failed += 1
            continue
        enc_key = bytes.fromhex(key_info["enc_key"])
        out_path = os.path.join(out_dir, rel)
        _print(f"解密: {rel} ({sz / 1024 / 1024:.1f}MB) ...", end=" ")
        if _decrypt_database(path, out_path, enc_key):
            try:
                import sqlite3
                conn = sqlite3.connect(out_path)
                tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                conn.close()
                _print(f"  OK! 表: {', '.join(t[0] for t in tables[:5])}")
                success += 1
                total_bytes += sz
            except Exception as e:
                _print(f"  [WARN] SQLite 验证失败: {e}")
                failed += 1
        else:
            failed += 1

    _print(f"\n{'=' * 60}")
    _print(f"结果: {success} 成功, {failed} 失败, 共 {len(db_files)} 个")
    _print(f"解密数据量: {total_bytes / 1024 / 1024 / 1024:.1f}GB")
    return {"success": success, "failed": failed, "total": len(db_files), "total_bytes": total_bytes}


# ============================================================
# CLI
# ============================================================

def cmd_extract(args: argparse.Namespace) -> None:
    db_dir = args.db_dir or auto_detect_db_dir()
    if not db_dir:
        _print("[ERROR] 未能自动检测微信数据库目录，请使用 --db-dir 手动指定")
        sys.exit(1)
    _print(f"[*] 数据库目录: {db_dir}")

    db_files, salt_to_dbs = collect_db_files(db_dir)
    if not db_files:
        _print(f"[ERROR] 在 {db_dir} 未找到可解密的 .db 文件")
        sys.exit(1)

    out_file = args.output

    # 第 1 级：已保存的 passphrase（若通过 set-passphrase 手动填入过）
    passphrase_hex = load_passphrase()
    if passphrase_hex:
        _print("[*] 使用已保存的 passphrase 派生密钥（PBKDF2，约需 30-60 秒）...")
        key_map = _derive_keys_from_passphrase(bytes.fromhex(passphrase_hex), db_files, salt_to_dbs)
        if key_map:
            _print(f"[+] passphrase 派生成功: {len(key_map)}/{len(salt_to_dbs)} 密钥")
            _save_results(db_files, salt_to_dbs, key_map, db_dir, out_file)
            if args.decrypt:
                decrypt_all(db_dir, "decrypted", out_file)
            return
        _print("[!] 已保存的 passphrase 无效，改走内存扫描")

    # 第 2 级：内存扫描 raw key（仅对仍缓存明文密钥的微信版本有效）
    _scan_memory_raw_key(db_dir, out_file)
    if args.decrypt:
        decrypt_all(db_dir, "decrypted", out_file)


def cmd_capture_experimental(args: argparse.Namespace) -> None:
    """[实验性/未验证] 尝试断点捕获 passphrase，见文件头 EXPERIMENTAL 段落说明。"""
    _print("!" * 60)
    _print("! 这是实验性、未经真机验证的方案，随时可能因为技术假设不成立而失败 !")
    _print("!" * 60)
    _print()
    _print("请在捕获期间于微信中执行：设置 -> 退出登录 -> 重新登录")
    _print(f"工具将等待最多 {args.timeout} 秒...")
    try:
        passphrase_hex = capture_passphrase_experimental(pid=args.pid, timeout=args.timeout)
    except ExperimentalCaptureError as e:
        _print(f"[ERROR] {e}")
        sys.exit(1)
    _print(f"[?] 断点命中并解析出一段 32 字节数据: {passphrase_hex[:8]}...（已截断，未验证是否真的是 passphrase）")
    save_passphrase(passphrase_hex)
    _print("[*] 已保存。运行 extract 会尝试用它派生密钥并做 HMAC 校验——校验通过才说明真的抓对了。")


def cmd_set_passphrase(args: argparse.Namespace) -> None:
    """手动写入通过其他手段（x64dbg/WinDbg/Frida 等）拿到的 passphrase。"""
    ph = args.passphrase.strip().lower()
    if len(ph) != 64 or not re.fullmatch(r"[0-9a-f]{64}", ph):
        _print("[ERROR] passphrase 必须是 64 位十六进制字符串（32 字节）")
        sys.exit(1)
    save_passphrase(ph)
    _print("[+] 已保存，下次运行 extract 会优先尝试用它派生密钥")


def cmd_decrypt(args: argparse.Namespace) -> None:
    db_dir = args.db_dir
    if not db_dir and os.path.exists(args.keys):
        try:
            with open(args.keys, encoding="utf-8") as f:
                db_dir = json.load(f).get("_db_dir")
        except Exception:
            pass
    db_dir = db_dir or auto_detect_db_dir()
    if not db_dir:
        _print("[ERROR] 未能确定数据库目录，请使用 --db-dir 手动指定")
        sys.exit(1)
    decrypt_all(db_dir, args.output, args.keys)


def main() -> None:
    parser = argparse.ArgumentParser(description="wcdb-key-tool (Windows) — 微信数据库密钥提取工具")
    parser.add_argument("--verbose", "-v", action="store_true")
    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    extract_cmd = sub.add_parser("extract", help="提取数据库密钥（内存扫描，仅老版本微信）")
    extract_cmd.add_argument("--db-dir", help="微信 db_storage 目录（默认自动检测）")
    extract_cmd.add_argument("--output", default="all_keys.json")
    extract_cmd.add_argument("--decrypt", action="store_true")

    capture_cmd = sub.add_parser(
        "capture-experimental",
        help="[实验性/未验证] 断点捕获 passphrase，见文件头 EXPERIMENTAL 段落",
    )
    capture_cmd.add_argument("--pid", type=int, help="微信进程 PID（默认自动查找）")
    capture_cmd.add_argument("--timeout", type=int, default=DEFAULT_CDB_TIMEOUT)

    passphrase_cmd = sub.add_parser("set-passphrase", help="手动填入通过其他手段获取的 passphrase")
    passphrase_cmd.add_argument("passphrase", help="64 位十六进制字符串（32 字节）")

    decrypt_cmd = sub.add_parser("decrypt", help="解密数据库（需要已有密钥文件）")
    decrypt_cmd.add_argument("--db-dir")
    decrypt_cmd.add_argument("--keys", default="all_keys.json")
    decrypt_cmd.add_argument("--output", default="decrypted")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.command == "extract":
        cmd_extract(args)
    elif args.command == "capture-experimental":
        cmd_capture_experimental(args)
    elif args.command == "set-passphrase":
        cmd_set_passphrase(args)
    elif args.command == "decrypt":
        cmd_decrypt(args)


if __name__ == "__main__":
    main()
