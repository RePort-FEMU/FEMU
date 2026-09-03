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
| `qemu-system-arm`, `qemu-system-mips` | Firmware emulation (the `qemu-system-mips` package also provides `qemu-system-mipsel`) |
| `iproute2` (`ip`) | TAP network interface setup |
| `e2fsprogs` (`mke2fs`), `util-linux` (`losetup`, `mount`, `fdisk`) | Raw image preparation |
| `iputils-ping` | Reachability checks |
| `file`, `binutils` | Init binary type detection |
| `sudo` | Privilege escalation for TAP/mount ops |
| `binwalk`-family extraction tools: `unzip`, `7zip`/`p7zip`, `squashfs-tools`, `sasquatch`, `zstd`, `lz4`, `lzop`, `cpio`, `cabextract`, `unrar`, `sleuthkit` | Firmware image extraction (used by the [`femu-extractor`](https://github.com/RePort-FEMU/extractor) dependency) |

See the [Dockerfile](Dockerfile) for the exact, currently-tested package list.

**Python:** 3.10+

---

## Docker (recommended)

FEMU needs to create TAP network interfaces and mount raw filesystem images, both of which require administrative privileges. Inside Docker this is contained by the `--privileged` container itself; run outside Docker and FEMU will instead shell out to `sudo` on your host for those steps — you'll be prompted for your sudo password, and it's running as root directly on your machine rather than inside a sandbox. **Docker is the recommended way to run FEMU** for this reason; see [Installation](#installation) below only if you need to run natively.

A pre-built image is published to GHCR on every push to `main` (see [.github/workflows/docker.yml](.github/workflows/docker.yml)).

```bash
docker run --rm \
    --privileged \
    --device /dev/net/tun \
    -v "/path/to/firmware.bin:/input/firmware.bin:ro" \
    -v "$(pwd)/output:/output" \
    ghcr.io/report-femu/femu:main \
    -m check -i /input/firmware.bin
```

`--privileged` is required for TAP interface setup and image mounting inside the container. `--device /dev/net/tun` is required for TAP networking. The entrypoint always writes to `/output`, so only mount your firmware and an output directory.

To build the image locally instead of pulling it:

```bash
docker build -t femu .
```

---

## Installation

Running natively (outside Docker) requires `sudo` on the host — FEMU shells out to it for TAP interface setup and filesystem mounting, so you'll be prompted for your password and those steps run as root on your actual machine. If that's not acceptable, use [Docker](#docker-recommended) instead.

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

### 3. (Optional) Start a PostgreSQL database

A PostgreSQL database enables brand detection and filesystem indexing. FEMU works without it (pass no `-sql` flag), but some features will be unavailable. There is currently no bundled setup script — start a container and load the schema yourself:

```bash
docker run -d \
    --name femu-postgres \
    -e POSTGRES_USER=femu \
    -e POSTGRES_PASSWORD=femu \
    -e POSTGRES_DB=firmware \
    -p 5432:5432 \
    postgres

docker exec -i femu-postgres psql -U femu -d firmware < database/schema
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
| `-s`, `--scripts` | Path to the guest-side init injection scripts | bundled with the package |
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
femu -m check -i firmware.bin -sql 127.0.0.1 -p 5432
```

---

## Output

Each firmware run produces a `findings.json` in `<output>/workDir/<tag>/`:

```jsonc
{
  "stage": "success",              // or "probe_failed", "extract_failed", "incompatible_arch", …
  "firmware": { "path": "…", "tag": "…", "brand": "…" },
  "emulation": {
    "imagePath": "…/raw.img", "architecture": "arm", "endianness": "LSB",
    "kernelPath": "…", "kernelVersion": "…", "initArg": "rdinit=…", "workDir": "…"
  },
  "initInjection": { "modifiedGuestFile": "…", "injectedContent": "…" },
  "network": {
    "networkType": "bridge",
    "candidates": [{ "ip": "192.168.0.1", "interface": "eth0", "bridge": "…", "vlans": [], "macs": [] }],
    "ports": [{ "port": 80, "proto": "tcp" }],
    "isUserNetwork": false,
    "hostIps": ["192.168.0.100"],
    "reachability": {
      "reachable": true, "webReachable": true,
      "checks": [{ "ip": "192.168.0.1", "port": 80, "kind": "http", "reachable": true, "responseTime": 1.2 }]
    }
  },
  "services": { "…": "…" },
  "timings": { "extractionSeconds": 3.1, "preparationSeconds": 5.4, "preEmulationSeconds": 20.7, "serviceResponseSeconds": 1.2 }
}
```

---

## Project structure

```
FEMU/
├── src/femu/                    Python package
│   ├── __main__.py              CLI entry point
│   ├── emulator.py              Top-level orchestration (explore/boot/debug/analyze)
│   ├── emulatorConfig.py        Run configuration
│   ├── extraction/              Firmware extraction + architecture detection
│   ├── imagePreparation/        Raw filesystem image preparation
│   ├── preEmulator/             Network probing, classification, verification
│   ├── qemuInterface.py         QEMU process management
│   ├── findings.py              findings.json build / load / export
│   ├── db.py, dbInterface.py    PostgreSQL persistence
│   └── scripts/firmadyne/       Guest-side init injection scripts
├── database/schema              PostgreSQL schema (see Installation step 3)
├── download.sh                  Downloads binaries from FirmAE/FEMU kernel releases
├── docker-entrypoint.sh         Docker container entrypoint
└── Dockerfile
```

---

## Citation

FEMU is the subject of an undergraduate thesis at the National and Kapodistrian University of Athens, Department of Informatics and Telecommunications:

> Georgios Nikolaidis, *"FEMU: A Full System Firmware Emulation Platform for IoT Devices"*, National and Kapodistrian University of Athens, 2026. [https://pergamos.lib.uoa.gr/uoa/dl/object/5426046](https://pergamos.lib.uoa.gr/uoa/dl/object/5426046)

```bibtex
@thesis{nikolaidis2026femu,
  title  = {FEMU: A Full System Firmware Emulation Platform for IoT Devices},
  author = {Nikolaidis, Georgios},
  school = {National and Kapodistrian University of Athens},
  year   = {2026},
  url    = {https://pergamos.lib.uoa.gr/uoa/dl/object/5426046}
}
```

---

## Credits

FEMU builds on top of [FirmAE](https://github.com/pr0v3rbs/FirmAE) by pr0v3rbs et al. The emulation kernels and busybox binaries are redistributed from the FirmAE project releases.

## License

[MIT](LICENSE)
