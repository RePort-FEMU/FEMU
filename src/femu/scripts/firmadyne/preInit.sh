#!/bin/sh

BUSYBOX=/firmadyne/busybox

[ -d /dev ] || ${BUSYBOX} mkdir -p /dev
[ -d /root ] || ${BUSYBOX} mkdir -p /root
[ -d /sys ] || ${BUSYBOX} mkdir -p /sys
[ -d /proc ] || ${BUSYBOX} mkdir -p /proc
[ -d /tmp ] || ${BUSYBOX} mkdir -p /tmp
${BUSYBOX} mkdir -p /var/lock

${BUSYBOX} mount -t sysfs sysfs /sys
${BUSYBOX} mount -t proc proc /proc
${BUSYBOX} ln -sf /proc/mounts /etc/mtab

${BUSYBOX} mkdir -p /dev/pts
${BUSYBOX} mount -t devpts devpts /dev/pts
${BUSYBOX} mount -t tmpfs tmpfs /run

# Emulation has no real entropy source, so the kernel's random pool initializes
# at a non-deterministic time (seconds to minutes). Services that read
# /dev/random to generate crypto material (e.g. TLS keys) block until then,
# which makes boots flaky. Repoint /dev/random at urandom's device node (1,9)
# so reads never block on the entropy pool.
${BUSYBOX} rm -f /dev/random
${BUSYBOX} mknod -m 444 /dev/random c 1 9

