FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    # QEMU emulators + ROM files (vgabios, efi-e1000, etc.)
    qemu-system-arm qemu-system-mips qemu-system-data \
    # Image preparation
    e2fsprogs util-linux fdisk\
    # Network / privilege
    iproute2 sudo iputils-ping \
    # File type detection
    file \
    # Archive & filesystem extraction (binwalk runtime deps)
    unzip 7zip squashfs-tools \
    zstd lz4 lzop cpio cabextract \
    liblzma5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /femu
COPY . .

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential pkg-config libfontconfig-dev git wget \
    && wget -q https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-6/sasquatch_1.0_amd64.deb \
    && dpkg -i sasquatch_1.0_amd64.deb && rm sasquatch_1.0_amd64.deb \
    && ./download.sh /femu/binaries \
    && pip install --no-cache-dir . jefferson ubi-reader \
    && apt-get purge -y build-essential pkg-config libfontconfig-dev git wget \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /root/.cache

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

VOLUME ["/input", "/output"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh", "-o", "/output"]
