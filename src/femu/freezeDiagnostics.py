"""
Freeze diagnostics for emulated guests.

When a guest's serial output stalls while QEMU is still alive, the guest has
wedged. These helpers snapshot the guest CPU over the QEMU monitor, resolve the
program counter against the kernel symbol table, and classify the freeze as
IDLE/blocked (CPU parked in the idle loop — a sleeping/blocked task, e.g. a
userspace or libnvram deadlock) versus BUSY/spin (CPU looping in kernel code).
The result is written to a sidecar '<serial-log>.freeze.txt'.
"""
import re
import os
import time
import bisect
import socket
import logging
import subprocess

from .common import Architecture, Endianess

logger = logging.getLogger(__name__)

# --- watchdog tuning --------------------------------------------------------
# A booting firmadyne guest emits kernel hooks on every syscall, so the serial
# log grows continuously. If it goes silent while QEMU is still alive, the guest
# has wedged. These thresholds decide when to snapshot the guest CPU state.
FREEZE_MIN_BOOT  = 15.0   # don't arm the watchdog during early boot
FREEZE_STALL     = 20.0   # serial log unchanged this long => treat as frozen
FREEZE_MIN_BYTES = 2000   # ignore stalls before the guest produced real output

# Kernel idle entry points (MIPS + ARM). PC parked here on every sample means
# the CPU is halted and the stuck task is sleeping/blocked, not busy-spinning.
_IDLE_SYMS = {
    "r4k_wait", "__r4k_wait", "r4k_wait_irqoff", "cpu_wait",
    "cpu_idle", "arch_cpu_idle", "default_idle", "cpu_startup_entry", "do_idle",
}

# kernel_path -> (sorted [(addr, name)], [addr]); built once per kernel via nm.
_symbol_cache: dict[str, tuple[list[tuple[int, str]], list[int]]] = {}


def query_monitor(monitor_path: str, command: str, timeout: float = 4.0) -> str:
    """Send an HMP command to a QEMU monitor unix socket and return its reply."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(monitor_path)
            time.sleep(0.2)
            try:
                s.recv(65536)   # drain greeting
            except Exception:
                pass
            s.sendall(f"{command}\n".encode())
            time.sleep(0.4)
            chunks = []
            try:
                while True:
                    d = s.recv(65536)
                    if not d:
                        break
                    chunks.append(d)
            except Exception:
                pass
            text = b"".join(chunks).decode(errors="replace")
            # Strip the HMP command echo (ANSI cursor sequences) so the reply
            # parses cleanly and reads nicely in the report.
            return re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', text).replace('\r', '')
    except Exception as e:
        logger.warning(f"Monitor query '{command}' failed: {e}")
        return ""


def _load_kernel_symbols(kernel_path: str) -> tuple[list[tuple[int, str]], list[int]]:
    """Parse the kernel's text symbol table (via nm), cached per kernel path."""
    cached = _symbol_cache.get(kernel_path)
    if cached is not None:
        return cached
    syms: list[tuple[int, str]] = []
    try:
        out = subprocess.run(["nm", "-n", kernel_path],
                             capture_output=True, text=True, timeout=30)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] in "tTwW":
                try:
                    syms.append((int(parts[0], 16), parts[2]))
                except ValueError:
                    pass
    except Exception as e:
        logger.warning(f"Could not load kernel symbols from {kernel_path}: {e}")
    syms.sort()
    result = (syms, [a for a, _ in syms])
    _symbol_cache[kernel_path] = result
    return result


def _resolve_sym(kernel_path: str, addr: int | None) -> str:
    """Resolve a guest kernel address to 'symbol+offset'."""
    if not addr:
        return "?"
    syms, addrs = _load_kernel_symbols(kernel_path)
    if not syms:
        return f"{addr:#x}"
    i = bisect.bisect_right(addrs, addr) - 1
    if i < 0:
        return f"{addr:#x}"
    base, name = syms[i]
    return f"{name}+{addr - base:#x}"


def _parse_guest_regs(text: str, arch: Architecture) -> dict:
    """Extract PC/RA/SP(/EPC) from an 'info registers' reply (MIPS or ARM)."""
    regs: dict[str, int | None] = {}

    def grab(pat: str) -> int | None:
        m = re.search(pat, text)
        return int(m.group(1), 16) if m else None

    if arch == Architecture.ARM:
        regs["pc"] = grab(r'R15=([0-9a-fA-F]{8})')
        regs["ra"] = grab(r'R14=([0-9a-fA-F]{8})')
        regs["sp"] = grab(r'R13=([0-9a-fA-F]{8})')
    else:  # MIPS
        regs["pc"]  = grab(r'pc=0x([0-9a-fA-F]{8})')
        regs["ra"]  = grab(r'\bra\s+([0-9a-fA-F]{8})')
        regs["sp"]  = grab(r'\bsp\s+([0-9a-fA-F]{8})')
        regs["epc"] = grab(r'EPC\s+0x([0-9a-fA-F]{8})')
    return regs


def _disassemble(monitor_path: str, addr: int, count: int = 8) -> str:
    """Disassemble `count` guest instructions at `addr` via the monitor (x/Ni)."""
    out = query_monitor(monitor_path, f"x/{count}i {addr:#x}")
    # Keep only the disassembly lines ("0x<addr>: <insn>"); this drops the HMP
    # command echo, which QEMU sign-extends addresses (0xffffffff...) so a plain
    # address match wouldn't catch it.
    lines = [ln for ln in out.splitlines() if re.match(r'\s*0x[0-9a-fA-F]+:', ln)]
    return "\n".join(lines).strip()


def capture_freeze_state(monitor_path: str, kernel_path: str,
                         arch: Architecture, endianness: Endianess,
                         log_path: str, elapsed: float,
                         samples: int = 6, interval: float = 0.5) -> None:
    """
    The guest's serial output has stalled while QEMU is still alive. Sample the
    guest CPU over the monitor, resolve the program counter against the kernel
    symbol table, classify idle-vs-spin, and write a sidecar
    '<log>.freeze.txt' report next to the serial log.
    """
    out_path = log_path + ".freeze.txt"
    rows: list[tuple[dict, str]] = []
    raw0 = ""
    idle_hits = 0
    for i in range(samples):
        reg = query_monitor(monitor_path, "info registers")
        if i == 0:
            raw0 = reg
        regs = _parse_guest_regs(reg, arch)
        pc_sym = _resolve_sym(kernel_path, regs.get("pc"))
        if pc_sym.split("+")[0] in _IDLE_SYMS:
            idle_hits += 1
        rows.append((regs, pc_sym))
        time.sleep(interval)

    blocked = idle_hits == samples and samples > 0
    if blocked:
        verdict = ("IDLE — the CPU was parked in the kernel idle loop on every "
                   "sample, so the guest is NOT busy-spinning. Either the boot "
                   "has wedged with every task blocked/sleeping in the kernel "
                   "(waiting on a lock, I/O or a page fault — e.g. the libnvram "
                   "semaphore), or the device simply finished booting and is "
                   "legitimately idle. If serial output was still expected (a "
                   "probe that never reached network setup), read it as a "
                   "BLOCKED task, not a kernel spin.")
    else:
        verdict = ("BUSY — the CPU was executing kernel code (not the idle loop) "
                   "while serial output was frozen. This points to a kernel-side "
                   "spin/loop; see the PC distribution below.")

    # Disassemble the distinct addresses the CPU is bouncing between (the
    # PC/EPC the samples landed on) — for a spin this shows the exact
    # instructions it can't get past (e.g. the kretprobe_trampoline breakpoint).
    disasm_addrs: list[int] = []
    for regs, _ in rows:
        for key in ("pc", "epc"):
            a = regs.get(key)
            if a and a not in disasm_addrs:
                disasm_addrs.append(a)
    disasm = [(a, _resolve_sym(kernel_path, a),
               _disassemble(monitor_path, a)) for a in disasm_addrs[:4]]

    try:
        with open(out_path, "w") as f:
            f.write("# FEMU freeze diagnostic\n")
            f.write(f"# log:     {os.path.basename(log_path)}\n")
            f.write(f"# kernel:  {kernel_path}\n")
            f.write(f"# arch:    {arch.name} {endianness.name}\n")
            f.write(f"# stalled: ~{elapsed:.1f}s into the run; serial output frozen\n")
            f.write(f"# idle samples: {idle_hits}/{samples}\n\n")
            f.write(f"VERDICT: {verdict}\n\n")
            for i, (regs, pc_sym) in enumerate(rows):
                line = f"[sample {i}] PC={pc_sym}"
                if regs.get("ra"):
                    line += f"   RA={_resolve_sym(kernel_path, regs['ra'])}"
                if regs.get("epc"):
                    line += f"   EPC={_resolve_sym(kernel_path, regs['epc'])}"
                if regs.get("sp"):
                    line += f"   SP={regs['sp']:#x}"
                f.write(line + "\n")
            if disasm:
                f.write("\n# disassembly at the addresses the CPU is bouncing between:\n")
                for a, sym, text in disasm:
                    f.write(f"\n## {a:#x}  ({sym})\n")
                    f.write((text or "(no output / unmapped)") + "\n")

            f.write("\n# raw 'info registers' (sample 0):\n")
            # Trim the echoed command prefix; start at the first register line.
            for marker in ("CPU#", "R00=", "pc="):
                idx = raw0.find(marker)
                if idx != -1:
                    raw0 = raw0[idx:]
                    break
            f.write(raw0.replace("(qemu)", "").strip() + "\n")
        logger.warning(
            f"Guest serial stalled ~{elapsed:.0f}s in — freeze diagnostic → "
            f"{out_path} (verdict: {'IDLE/blocked' if blocked else 'BUSY/spin'})")
    except Exception as e:
        logger.warning(f"Failed to write freeze diagnostic: {e}")
