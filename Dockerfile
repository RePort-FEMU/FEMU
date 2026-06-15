FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# --- Runtime system packages (rarely change → cached) ---
# unrar (RARLAB) lives in Debian's non-free component, so enable it first.
RUN sed -i 's/Components: main/Components: main non-free/' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y \
    # QEMU emulators + ROM files (vgabios, efi-e1000, etc.)
    qemu-system-arm qemu-system-mips \
    # Image preparation
    e2fsprogs util-linux fdisk \
    # Network / privilege
    iproute2 sudo iputils-ping \
    # File type detection (libmagic for python-magic)
    file binutils \
    # Archive & filesystem extraction (binwalk runtime deps)
    unzip 7zip squashfs-tools \
    zstd lz4 lzop cpio cabextract \
    liblzma5 \
    # rar archives + ext/fat filesystem extraction (sleuthkit: tsk_recover/fls/icat)
    unrar sleuthkit \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /femu

# --- Heavy, source-independent setup (cached unless download.sh changes) ---
# Firmware kernels/binaries, sasquatch, and Python dependencies live in their
# own layer BEFORE the source is copied, so editing FEMU code does NOT
# re-download kernels or reinstall dependencies. Only download.sh is copied
# here (the source comes later), so this layer's cache survives code changes.
# NOTE: keep the dependency list in sync with pyproject.toml [project.dependencies].
COPY download.sh ./
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential pkg-config libfontconfig-dev git wget \
    && wget -q https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-6/sasquatch_1.0_amd64.deb \
    && dpkg -i sasquatch_1.0_amd64.deb && rm sasquatch_1.0_amd64.deb \
    && ./download.sh /femu/binaries \
    && pip install --no-cache-dir \
        "femu-extractor @ git+https://github.com/RePort-FEMU/extractor@master" \
        "psycopg2-binary>=2.9" \
        jefferson ubi-reader \
    && apt-get purge -y build-essential pkg-config libfontconfig-dev git wget \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /root/.cache

# --- Application source: only this layer (and the install below) rebuild on a code change ---
COPY . .
RUN pip install --no-cache-dir --no-deps .

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

VOLUME ["/input", "/output"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh", "-o", "/output"]
