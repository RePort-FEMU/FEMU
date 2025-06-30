#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <cstring>
#include <stdexcept>
#include <string>       
#include <sys/mount.h>

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        std::cerr << "This program must be run as root." << std::endl;
        return 1;
    }
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <loopDevice> <mountPoint>" << std::endl;
        return 1;
    }

    const char *loopDevice = argv[1];
    const char *mountPoint = argv[2];

    // Check that the loop device exists
    if (access(loopDevice, F_OK) != 0) {
        std::cerr << "Loop device " << loopDevice << " does not exist." << std::endl;
        return 1;
    }

    if (mount(loopDevice, mountPoint, "ext2", 0, nullptr) < 0) {
        perror("Failed to mount loop device");
        std::cerr << "Error code: " << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    std::cout << "Mounted " << loopDevice << " on " << mountPoint << std::endl;

    std::cout << "Partition mounted successfully at /mnt" << std::endl;
    return 0;
}