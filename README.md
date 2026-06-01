# FEMU — Firmware Emulation Framework

FEMU automates the emulation of embedded Linux firmware images (routers, cameras, IoT devices). It extracts the filesystem and kernel, probes the network configuration, and boots the firmware under QEMU — giving you a live, reachable device to interact with or analyze.

It builds on the ideas of [FirmAE](https://github.com/pr0v3rbs/FirmAE) with a cleaner Python architecture, a proper package structure, and structured findings output.

---

## Supported architectures

| Architecture | Endianness |
|---|---|
| MIPS | Big-endian, Little-endian |
| ARM | Little-endian |

---

## Requirements

**System tools** (must be installed on the host or available in the Docker image):

| Tool | Purpose |
|---|---|
| `qemu-system-arm`, `qemu-system-mips`, `qemu-system-mipsel` | Firmware emulation |
| `iproute2` (`ip`) | TAP network interface setup |
| `e2fsprogs` (`mke2fs`), `util-linux` (`losetup`) | Raw image preparation |
| `mount` / `umount` | Filesystem mounting |
| `iputils-ping` | Reachability checks |
| `file` | Init binary type detection |
| `sudo` | Privilege escalation for TAP/mount ops |

**Python:** 3.10+

---

## Installation

### 1. Clone and install

```bash
git clone https://github.com/RePort-FEMU/FEMU
cd FEMU
pip install -e .
```

### 2. Download emulation binaries

The firmware emulation kernels and busybox binaries are not bundled with the package and must be downloaded separately:

```bash
./download.sh          # downloads to ./binaries/
```

Or, if you installed via pip without cloning:

```bash
curl -fsSL https://raw.githubusercontent.com/RePort-FEMU/FEMU/main/download.sh | sh
```

### 3. (Optional) Start the PostgreSQL database

A PostgreSQL database enables brand detection and filesystem indexing. FEMU works without it, but some features will be unavailable.

```bash
./install.sh    # starts a femu-postgres Docker container and applies the schema
```

---

## Usage

### Command line

```
femu -i <firmware> [options]
```

| Flag | Description | Default |
|---|---|---|
| `-i`, `--input` | Path to firmware image or directory of images | required |
| `-m`, `--mode` | `check` / `boot` / `debug` / `analyze` | `boot` |
| `-o`, `--output` | Output directory for results and images | `./output` |
| `-b`, `--brand` | Firmware brand (e.g. `TP-Link`) | `auto` |
| `-bin`, `--binaries` | Path to emulation binaries | `./binaries` |
| `-sql` | PostgreSQL host IP | none |
| `-p`, `--port` | PostgreSQL port | `5432` |
| `--debug` | Enable shell access in guest (nc:31337, telnet:31338) | off |

### Modes

| Mode | What it does |
|---|---|
| `check` | Full exploration pipeline: extract, probe network, verify reachability, write `findings.json` |
| `boot` | Load existing findings and boot the firmware (24h session) |
| `debug` | Same as boot with a shell listener inside the guest |
| `analyze` | Print a summary of existing findings |

### Examples

```bash
# Explore a firmware image (run this first)
femu -m check -i firmware.bin

# Boot it
femu -m boot -i firmware.bin

# Boot with an interactive shell inside the guest
femu -m debug -i firmware.bin --debug

# Run against a whole directory of images
femu -m check -i ./firmwares/

# With database
femu -m check -i firmware.bin -sql 127.0.0.1 -p 4321
```

---

## Docker

### Using the pre-built image

```bash
docker run --rm \
    --privileged \
    --device /dev/net/tun \
    -v "$(pwd):/workspace" \
    -w /workspace \
    ghcr.io/rePort-FEMU/FEMU:main \
    -m check -i ./firmwares/router.bin -o ./output
```

`--privileged` is required for TAP interface setup and image mounting inside the container.

### Using femu.sh (recommended)

`femu.sh` is a convenience wrapper that handles the `docker run` flags, auto-detects the postgres container, and optionally builds the image locally:

```bash
# Start the database (once)
./install.sh

# Build locally and run
./femu.sh -m check -i ./firmwares/router.bin -o ./output

# Or use the pre-built registry image
FEMU_IMAGE=ghcr.io/rePort-FEMU/FEMU:main ./femu.sh -m check -i ./firmwares/router.bin
```

The `femu.sh` script:
- Builds the Docker image if it does not exist locally
- Auto-detects and connects to the running `femu-postgres` container
- Mounts your current directory into the container so relative paths work as-is

---

## Output

Each firmware run produces a `findings.json` in `<output>/workDir/<id>/`:

```jsonc
{
  "stage": "success",           // or "probe_failed", "extraction_failed", …
  "firmware": { "hash": "…", "brand": "…" },
  "emulation": { "architecture": "arm", "initArg": "rdinit=…", … },
  "network": {
    "networkType": "bridge",
    "candidates": [{ "ip": "192.168.0.1", "interface": "eth0", … }],
    "ports": [{ "port": 80, "proto": "tcp" }, …],
    "reachability": { "ping": true, "service": true }
  }
}
```

---

## Project structure

```
FEMU/
├── src/femu/             Python package
│   ├── emulator.py       Top-level orchestration (explore/boot/debug/analyze)
│   ├── preEmulator.py    Network probe pipeline
│   ├── qemuInterface.py  QEMU process management
│   ├── prepareImage.py   Filesystem preparation
│   └── scripts/firmadyne/  Guest-side init injection scripts
├── download.sh           Downloads binaries from FirmAE releases
├── install.sh            Starts the PostgreSQL Docker container
├── femu.sh               Docker run wrapper
└── Dockerfile
```

---

## Credits

FEMU builds on top of [FirmAE](https://github.com/pr0v3rbs/FirmAE) by pr0v3rbs et al. The emulation kernels and busybox binaries are redistributed from the FirmAE project releases.
