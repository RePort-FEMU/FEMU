// This script unmounts the image file from the loopback device and releases the loop device.

#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/loop.h>
#include <sys/stat.h>
#include <cstring>
#include <stdexcept>
#include <string>       
#include <sys/mount.h>
#include <mntent.h>
#include <limits.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <loop_device_or_mount_point>" << std::endl;
        return 1;
    }

    const char *input = argv[1];
    char absInput[PATH_MAX];
    if (input[0] != '/') {
        if (!realpath(input, absInput)) {
            perror("Failed to resolve absolute path");
            return 1;
        }
        input = absInput;
    }

    std::string loopDevice;

    struct stat st;
    if (stat(input, &st) == 0 && S_ISBLK(st.st_mode)) {
        // Input is a block device (loop device)
        loopDevice = input;
    } else {
        // Assume input is a mount point, try to find the backing loop device
        FILE *mnt = setmntent("/proc/mounts", "r");
        if (!mnt) {
            perror("Failed to open /proc/mounts");
            return 1;
        }
        struct mntent *ent;
        bool found = false;
        while ((ent = getmntent(mnt)) != nullptr) {
            if (strcmp(ent->mnt_dir, input) == 0) {
                loopDevice = ent->mnt_fsname;
                found = true;
                break;
            }
        }
        endmntent(mnt);
        if (!found) {
            std::cerr << "Could not find loop device for mount point: " << input << std::endl;
            return 1;
        }
    }

    // Unmount the mount point or device
    if (umount(input) < 0) {
        perror("Failed to unmount");
        return 1;
    }

    // Open the loop device
    int loopFd = open(loopDevice.c_str(), O_RDWR);
    if (loopFd < 0) {
        perror("Failed to open loop device");
        return 1;
    }

    // Check if the loop device is associated with a file before clearing
    struct loop_info64 loopinfo;
    if (ioctl(loopFd, LOOP_GET_STATUS64, &loopinfo) < 0) {
        // Not associated, skip clearing
        std::cerr << "Loop device is not associated with any file, skipping clear." << std::endl;
        close(loopFd);
        std::cout << "Successfully unmounted " << loopDevice << std::endl;
        return 0;
    }

    // Release the loop device
    if (ioctl(loopFd, LOOP_CLR_FD, 0) < 0) {
        perror("Failed to clear loop device file descriptor");
        close(loopFd);
        return 1;
    }

    close(loopFd);
    std::cout << "Successfully unmounted and released " << loopDevice << std::endl;

    return 0;
}