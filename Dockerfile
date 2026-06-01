FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python runtime + build tools for pip git installs
    python3 python3-pip git wget \
    # QEMU emulators (arm, mipseb, mipsel)
    qemu-system-arm qemu-system-mips \
    # Image preparation: loop devices, ext2 filesystem creation
    e2fsprogs util-linux \
    # Privilege helpers used by TAP setup and mknod fallback
    iproute2 sudo \
    # Reachability checks
    iputils-ping \
    # Init-type detection in preEmulator
    file \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /femu

# Copy repo — .dockerignore keeps this lean
COPY . .

# Download firmware emulation binaries (kernels, busybox, etc.)
RUN ./download.sh /femu/binaries

# Install FEMU and its Python dependencies
RUN pip3 install --no-cache-dir -e .

# Running as root inside the container so sudo commands work without a password
# (root calling sudo is a no-op privilege-wise but satisfies the subprocess calls)

ENTRYPOINT ["python3", "-m", "femu", "--binaries", "/femu/binaries"]
