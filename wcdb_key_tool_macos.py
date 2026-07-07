#!/usr/bin/env python3
"""wcdb-key-tool (macOS) — 微信数据库密钥提取工具

macOS 微信数据库密钥提取工具。老版本走内存扫描，微信 4.1.10+ 走 LLDB
断点抓 passphrase + PBKDF2 派生，原理与 Linux 版（wcdb_key_tool.py）一致。

Usage:
    sudo python3 wcdb_key_tool_macos.py extract          # 提取密钥（首次需要重新登录微信）
    sudo python3 wcdb_key_tool_macos.py decrypt           # 解密数据库
    sudo python3 wcdb_key_tool_macos.py extract --decrypt  # 提取 + 解密一步完成

Requirements:
    - Python 3.10+
    - lldb（随 Xcode Command Line Tools 安装：xcode-select --install）
    - 微信需先 ad-hoc 重签名去除 Hardened Runtime（见下方 Prerequisite）
    - Root 权限（task_for_pid / lldb attach 需要）

Prerequisite（每次微信自动更新后可能需要重做一次）:
    sudo codesign --force --deep --sign - /Applications/WeChat.app
    然后重启微信

https://github.com/TANGandXUE/wcdb-key-tool
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import pathlib
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
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
# AES-CBC via CommonCrypto (macOS 系统自带，无需第三方依赖)
# ============================================================

_libSystem = ctypes.CDLL(ctypes.util.find_library("System"))
_libSystem.CCCrypt.argtypes = [
    ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_libSystem.CCCrypt.restype = ctypes.c_int32

_kCCDecrypt = 1
_kCCAlgorithmAES = 0


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-256-CBC 解密（无 padding），走 CommonCrypto 的 CCCrypt。"""
    out_buf = ctypes.create_string_buffer(len(data) + 32)
    out_len = ctypes.c_size_t(0)
    status = _libSystem.CCCrypt(
        _kCCDecrypt, _kCCAlgorithmAES, 0,  # options=0 -> 无 padding，SQLCipher 自管 padding
        key, len(key),
        iv,
        data, len(data),
        out_buf, len(out_buf),
        ctypes.byref(out_len),
    )
    if status != 0:
        raise RuntimeError(f"CCCrypt 解密失败: status={status}")
    return out_buf.raw[: out_len.value]


# ============================================================
# HMAC Verification（与 SQLCipher4 规范一致，跨平台通用）
# ============================================================

def verify_enc_key(enc_key: bytes, db_page1: bytes) -> bool:
    """通过 HMAC-SHA512 校验 page 1 验证 enc_key 是否正确。

    SQLCipher4 参数：
    - MAC salt = DB salt XOR 0x3A
    - MAC key = PBKDF2(enc_key, mac_salt, iterations=2, sha512, 32B)
    - HMAC 范围: page1[16:4032]
    - 存储的 HMAC: page1[4032:4096] (64B SHA512)
    """
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
    """遍历 db_dir 收集所有 .db 文件及其 salt。

    Returns:
        db_files: [(rel_path, abs_path, size, salt_hex, page1_bytes), ...]
        salt_to_dbs: {salt_hex: [rel_path, ...]}
    """
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
# 内存扫描（微信 4.0.x：raw key 仍以明文缓存在进程内存）
# ============================================================
#
# 前提：目标 App 需先重签名移除 Hardened Runtime（见文件头 Prerequisite），
# 否则内核会拒绝 task_for_pid。

KERN_SUCCESS = 0
VM_REGION_BASIC_INFO_64 = 9
VM_REGION_BASIC_INFO_COUNT_64 = 9
VM_PROT_READ = 0x01

_WECHAT_KEY_PATTERN = re.compile(rb"x'([0-9a-f]{96})'")


class vm_region_basic_info_64(ctypes.Structure):
    _fields_ = [
        ("protection", ctypes.c_int32),
        ("max_protection", ctypes.c_int32),
        ("inheritance", ctypes.c_uint32),
        ("shared", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("offset", ctypes.c_uint64),
        ("behavior", ctypes.c_int32),
        ("user_wired_count", ctypes.c_uint16),
    ]


class SignatureInvalidError(RuntimeError):
    """所有微信进程 task_for_pid 失败（签名被系统还原），需要重新执行重签名。"""


class KeysNotFoundError(RuntimeError):
    """能读内存但扫不到密钥（微信可能未登录，或已是 4.1.10+ 不再缓存明文密钥）。"""


def _task_for_pid(pid: int) -> int:
    task = ctypes.c_uint32(0)
    kr = _libSystem.task_for_pid(_libSystem.mach_task_self(), ctypes.c_int(pid), ctypes.byref(task))
    if kr != KERN_SUCCESS:
        raise PermissionError(
            f"task_for_pid failed for PID={pid} (kern_return={kr})。"
            "请确认已对微信执行重签名（见文件头 Prerequisite）并重启微信。"
        )
    return task.value


def _enum_readable_regions(task: int) -> list[tuple[int, int]]:
    regions: list[tuple[int, int]] = []
    address = ctypes.c_uint64(0)
    size = ctypes.c_uint64(0)
    info = vm_region_basic_info_64()
    info_count = ctypes.c_uint32(VM_REGION_BASIC_INFO_COUNT_64)
    object_name = ctypes.c_uint32(0)

    while True:
        kr = _libSystem.mach_vm_region(
            ctypes.c_uint32(task),
            ctypes.byref(address),
            ctypes.byref(size),
            ctypes.c_int(VM_REGION_BASIC_INFO_64),
            ctypes.byref(info),
            ctypes.byref(info_count),
            ctypes.byref(object_name),
        )
        if kr != KERN_SUCCESS:
            break

        reg_size = size.value
        if (info.protection & VM_PROT_READ) and 0 < reg_size < 500 * 1024 * 1024:
            regions.append((address.value, reg_size))

        next_addr = address.value + reg_size
        if next_addr <= address.value:
            break
        address.value = next_addr

    return regions


def _read_memory(task: int, address: int, size: int) -> bytes | None:
    data_ptr = ctypes.c_uint64(0)
    data_size = ctypes.c_uint64(0)
    kr = _libSystem.mach_vm_read(
        ctypes.c_uint32(task),
        ctypes.c_uint64(address),
        ctypes.c_uint64(size),
        ctypes.byref(data_ptr),
        ctypes.byref(data_size),
    )
    if kr != KERN_SUCCESS:
        return None
    try:
        return ctypes.string_at(data_ptr.value, data_size.value)
    finally:
        _libSystem.mach_vm_deallocate(_libSystem.mach_task_self(), data_ptr, data_size)


def _find_pids(process_name: str) -> list[int]:
    try:
        r = subprocess.run(["pgrep", "-x", process_name], capture_output=True, text=True)
        return [int(p) for p in r.stdout.strip().split() if p.strip().isdigit()]
    except (FileNotFoundError, ValueError):
        return []


def _scan_memory_raw_key(db_dir: str, keys_file: str) -> dict:
    """扫描微信进程内存，匹配 x'<64hex_enc_key><32hex_salt>' 明文密钥模式（微信 4.0.x）。"""
    db_files, salt_to_dbs = collect_db_files(db_dir)
    if not db_files:
        raise RuntimeError(f"在 {db_dir} 未找到可解密的 .db 文件")

    _print(f"找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的 salt")

    pids = _find_pids("WeChat")
    if not pids:
        raise RuntimeError("未找到微信进程，请先启动微信")
    _print(f"找到微信进程: {pids}")

    key_map: dict[str, str] = {}
    remaining_salts = set(salt_to_dbs.keys())
    task_ok_count = 0
    t0 = time.time()

    for pid in pids:
        if not remaining_salts:
            break
        _print(f"\n[*] 扫描 PID={pid}")
        try:
            task = _task_for_pid(pid)
            task_ok_count += 1
        except PermissionError as e:
            _print(f"[WARN] {e}")
            continue

        regions = _enum_readable_regions(task)
        total_mb = sum(s for _, s in regions) / 1024 / 1024
        _print(f"  {len(regions)} 个区域, {total_mb:.0f}MB")

        for base, size in regions:
            if not remaining_salts:
                break
            data = _read_memory(task, base, size)
            if not data:
                continue
            for m in _WECHAT_KEY_PATTERN.finditer(data):
                hex_str = m.group(1).decode()
                enc_key_hex, salt_hex = hex_str[:64], hex_str[64:]
                if salt_hex not in remaining_salts:
                    continue
                enc_key = bytes.fromhex(enc_key_hex)
                for rel, _path, _sz, s, page1 in db_files:
                    if s == salt_hex and verify_enc_key(enc_key, page1):
                        key_map[salt_hex] = enc_key_hex
                        remaining_salts.discard(salt_hex)
                        _print(f"  [FOUND] salt={salt_hex} enc_key={enc_key_hex}")
                        break

    _print(f"\n扫描完成: {time.time() - t0:.1f}s, {len(pids)} 个进程")

    if not key_map:
        if task_ok_count == 0:
            raise SignatureInvalidError(
                "所有微信进程都无法读取内存（task_for_pid 失败），微信签名可能被系统更新还原，需重新执行重签名。"
            )
        raise KeysNotFoundError("能读内存但未扫到密钥（微信可能未登录，或已是不再缓存明文密钥的新版本）")

    _save_results(db_files, salt_to_dbs, key_map, db_dir, keys_file)
    return key_map


# ============================================================
# LLDB 断点捕获（微信 4.1.10+：内存里只剩 passphrase，需断点系统函数）
# ============================================================
#
# 微信 4.1.10 起改为在内存中只保留 passphrase（不再是可直接使用的 raw key），
# SQLCipher4 派生密钥时调用的是苹果系统函数 CCKeyDerivationPBKDF
# （CommonCrypto 导出符号，系统自带，不需要对被剥符号的微信二进制做逆向）。
# 在该函数下断点，等待用户退出登录再重新登录（触发数据库重新打开 -> 重新派生），
# 从参数寄存器读出 32 字节 passphrase：
#   CCKeyDerivationPBKDF(alg, password, passwordLen, salt, saltLen, prf, rounds, ...)
#   arm64:  x1=password, x2=passwordLen(==32)
#   x86_64: rsi=password, rdx=passwordLen(==32)

DEFAULT_TIMEOUT = 180


class CaptureError(RuntimeError):
    pass


def check_lldb_prerequisites() -> list[str]:
    issues = []
    if not shutil.which("lldb"):
        issues.append("未检测到 lldb，请安装 Xcode Command Line Tools: xcode-select --install")
    return issues


def _find_wechat_pid() -> int | None:
    r = subprocess.run(["pgrep", "-x", "WeChat"], capture_output=True, text=True)
    pids = [int(p) for p in r.stdout.split() if p.strip().isdigit()]
    return pids[0] if pids else None


def _cleanup_lldb_orphans() -> None:
    for pat in (["pkill", "-9", "-x", "lldb"],
                ["pkill", "-9", "-f", "LLDB.framework.*debugserver"]):
        try:
            subprocess.run(pat, capture_output=True, timeout=5)
        except Exception:
            pass


def _parse_passphrase(out: str) -> str | None:
    """从 lldb `memory read --format x` 的 hexdump 中解析 32 字节 passphrase。"""
    by: list[str] = []
    for line in out.splitlines():
        m = re.match(r"\s*0x[0-9a-f]+:\s+((?:0x[0-9a-f]{2}\s*)+)$", line)
        if m:
            by += re.findall(r"0x([0-9a-f]{2})", m.group(1))
    return "".join(by[:32]) if len(by) >= 32 else None


def capture_passphrase_lldb(timeout: int = DEFAULT_TIMEOUT) -> str:
    """attach 微信进程，在 CCKeyDerivationPBKDF 上断点，等待用户重新登录触发命中。"""
    import platform

    issues = check_lldb_prerequisites()
    if issues:
        raise CaptureError("; ".join(issues))

    pid = _find_wechat_pid()
    if not pid:
        raise CaptureError("未找到微信进程，请先启动并登录微信")

    is_arm = platform.machine() in ("arm64", "aarch64")
    pw_reg, len_reg = ("x1", "x2") if is_arm else ("rsi", "rdx")

    script = (
        "settings set target.preload-symbols false\n"
        f"process attach -p {pid}\n"
        f"breakpoint set -n CCKeyDerivationPBKDF -c '${len_reg} == 32'\n"
        "breakpoint command add 1\n"
        f"memory read --size 1 --count 32 --format x ${pw_reg}\n"
        "detach\n"
        "quit\n"
        "DONE\n"
        "process continue\n"
    )
    fd, sp = tempfile.mkstemp(suffix=".lldb", prefix="wxcap_")
    with os.fdopen(fd, "w") as f:
        f.write(script)

    # 用 sleep 保活 stdin：lldb continue 后是异步的，必须等命中才能收尾，
    # 否则读到 EOF 就直接退出，根本等不到用户重新登录触发断点。
    proc = subprocess.Popen(
        ["bash", "-c", f"( cat {sp}; sleep {timeout} ) | TERM=dumb lldb"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    buf = ""
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            r, _, _ = select.select([proc.stdout], [], [], 3.0)
            if r:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                buf += line
            if _parse_passphrase(buf):
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
        try:
            os.unlink(sp)
        except OSError:
            pass
        _cleanup_lldb_orphans()

    ph = _parse_passphrase(buf)
    if ph:
        logger.info("LLDB passphrase 捕获成功")
        return ph
    raise CaptureError("未捕获到 passphrase，请确认捕获期间在微信内退出登录并重新登录")


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
# PBKDF2 Key Derivation（拿到 passphrase 后，两个平台通用）
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


# ============================================================
# Key helpers（同 Linux 版）
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
# Config Detection（自动检测微信数据目录 —— macOS 4.x 沙盒容器路径）
# ============================================================

def auto_detect_db_dir() -> str | None:
    """自动检测微信数据库目录。

    macOS 微信 4.x 数据存储在 App 沙盒容器内：
    ~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/<wxid>/db_storage
    """
    container_root = os.path.expanduser(
        "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
    )
    if not os.path.isdir(container_root):
        return None

    candidates = []
    for entry in os.listdir(container_root):
        db_storage = os.path.join(container_root, entry, "db_storage")
        if os.path.isdir(db_storage):
            candidates.append(db_storage)

    for candidate in candidates:
        for _ in pathlib.Path(candidate).rglob("*.db"):
            return candidate

    return candidates[0] if candidates else None


# ============================================================
# Database Decryption（与 Linux 版一致，仅底层 AES 实现换成 CommonCrypto）
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
    _print("  WeChat 数据库解密器 (macOS)")
    _print("=" * 60)

    if not os.path.exists(keys_file):
        _print(f"[ERROR] 密钥文件不存在: {keys_file}")
        _print("请先运行: sudo python3 wcdb_key_tool_macos.py extract")
        sys.exit(1)

    with open(keys_file, encoding="utf-8") as f:
        keys = json.load(f)
    keys = _strip_key_metadata(keys)
    _print(f"\n加载 {len(keys)} 个数据库密钥")
    _print(f"输出目录: {out_dir}")
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

    success = 0
    failed = 0
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
                table_names = [t[0] for t in tables]
                _print(f"  OK! 表: {', '.join(table_names[:5])}", end="")
                if len(table_names) > 5:
                    _print(f" ...共{len(table_names)}个", end="")
                _print()
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
    _print(f"解密文件在: {out_dir}")

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

    # === 第 1 级：已缓存的 keys ===
    if os.path.exists(out_file):
        try:
            with open(out_file, encoding="utf-8") as f:
                existing = _strip_key_metadata(json.load(f))
            if all(
                _get_key_info(existing, rel) and verify_enc_key(bytes.fromhex(_get_key_info(existing, rel)["enc_key"]), page1)
                for rel, _p, _s, _salt, page1 in db_files
            ):
                _print("[+] 已缓存的密钥全部验证通过，无需重新提取")
                if args.decrypt:
                    decrypt_all(db_dir, "decrypted", out_file)
                return
        except (json.JSONDecodeError, KeyError, ValueError):
            pass

    # === 第 2 级：已保存的 passphrase + PBKDF2 派生（微信 4.1.10+ 主路径）===
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
        _print("[!] 已保存的 passphrase 无效（微信可能已更新或换了账号），将重新尝试")

    # === 第 3 级：内存扫描 raw key（微信 4.0.x）===
    try:
        _scan_memory_raw_key(db_dir, out_file)
        if args.decrypt:
            decrypt_all(db_dir, "decrypted", out_file)
        return
    except SignatureInvalidError as e:
        _print(f"[ERROR] {e}")
        sys.exit(1)
    except KeysNotFoundError:
        _print("[*] 内存里没有明文密钥，微信应该是 4.1.10+ 版本，需要用 LLDB 抓 passphrase")

    # === 第 4 级：LLDB 断点捕获 passphrase ===
    _print()
    _print("=" * 60)
    _print("  需要捕获新的 passphrase")
    _print("=" * 60)
    _print()
    _print("请在微信中执行以下操作：")
    _print("  1. 打开微信设置")
    _print("  2. 退出登录（不是退出微信，是账号退出登录）")
    _print("  3. 重新扫码/输入密码登录")
    _print()
    _print(f"工具将等待最多 {args.timeout} 秒...")

    try:
        passphrase_hex = capture_passphrase_lldb(timeout=args.timeout)
    except CaptureError as e:
        _print(f"[ERROR] 捕获失败: {e}")
        sys.exit(1)

    _print(f"[+] passphrase 捕获成功: {passphrase_hex[:8]}...（已截断）")
    save_passphrase(passphrase_hex)

    _print("\n[*] 开始 PBKDF2 派生密钥（约需 30-60 秒）...")
    key_map = _derive_keys_from_passphrase(bytes.fromhex(passphrase_hex), db_files, salt_to_dbs)
    if not key_map:
        _print("[ERROR] PBKDF2 派生后未能验证任何密钥，请检查数据库目录")
        sys.exit(1)

    _save_results(db_files, salt_to_dbs, key_map, db_dir, out_file)
    if args.decrypt:
        decrypt_all(db_dir, "decrypted", out_file)


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
    parser = argparse.ArgumentParser(description="wcdb-key-tool (macOS) — 微信数据库密钥提取工具")
    parser.add_argument("--verbose", "-v", action="store_true")
    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    extract_cmd = sub.add_parser("extract", help="提取数据库密钥")
    extract_cmd.add_argument("--db-dir", help="微信 db_storage 目录（默认自动检测）")
    extract_cmd.add_argument("--output", default="all_keys.json")
    extract_cmd.add_argument("--decrypt", action="store_true")
    extract_cmd.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)

    decrypt_cmd = sub.add_parser("decrypt", help="解密数据库（需要已有密钥文件）")
    decrypt_cmd.add_argument("--db-dir")
    decrypt_cmd.add_argument("--keys", default="all_keys.json")
    decrypt_cmd.add_argument("--output", default="decrypted")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.command == "extract":
        cmd_extract(args)
    elif args.command == "decrypt":
        cmd_decrypt(args)


if __name__ == "__main__":
    main()
