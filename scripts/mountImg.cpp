// This script creates a loopback device and mount it from a given image file.

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

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        std::cerr << "This program must be run as root." << std::endl;
        return 1;
    }
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <image_file> <mount_point>" << std::endl;
        return 1;
    }

    const char *imageFile = argv[1];
    const char *mountPoint = argv[2];

    int loopCtrlFd = open("/dev/loop-control", O_RDWR);
    if (loopCtrlFd < 0) {
        perror("Failed to open /dev/loop-control");
        return 1;
    }

    int loopDevice = ioctl(loopCtrlFd, LOOP_CTL_GET_FREE);
    if (loopDevice < 0) {
        perror("Failed to get free loop device");
        close(loopCtrlFd);
        return 1;
    }
    
    std::string loopPath = "/dev/loop" + std::to_string(loopDevice);
    int loopFd = open(loopPath.c_str(), O_RDWR);
    if (loopFd < 0) {
        perror("Failed to open loop device");
        close(loopCtrlFd);
        return 1;
    }

    int imgFd = open(imageFile, O_RDWR);
    if (imgFd < 0) {
        perror("Failed to open image file");
        close(loopFd);
        close(loopCtrlFd);
        return 1;
    }

    // Associate the image file with the loop device
    if (ioctl(loopFd, LOOP_SET_FD, imgFd) < 0) {
        perror("Failed to set loop device file descriptor");
        close(imgFd);
        close(loopFd);
        close(loopCtrlFd);
        return 1;
    }

    struct loop_info64 loopInfo;
    memset(&loopInfo, 0, sizeof(loopInfo));
    strncpy(reinterpret_cast<char*>(loopInfo.lo_file_name), imageFile, LO_NAME_SIZE - 1);

    if (ioctl(loopFd, LOOP_SET_STATUS64, &loopInfo) < 0) {
        perror("Failed to set loop device info");
        ioctl(loopFd, LOOP_CLR_FD, 0);
        close(imgFd);
        close(loopFd);
        close(loopCtrlFd);
        return 1;
    }


    if (mount(loopPath.c_str(), mountPoint, "ext2", 0, nullptr) < 0) {
        perror("Failed to mount loop device");
        std::cerr << "Error code: " << errno << " (" << std::strerror(errno) << ")" << std::endl;
        ioctl(loopFd, LOOP_CLR_FD, 0);
        close(imgFd);
        close(loopFd);
        close(loopCtrlFd);
        return 1;
    }

    std::cout << "Mounted " << imageFile << " on " << mountPoint << std::endl;
    std::cout << "Loop device: " << loopPath << std::endl;

    // Cleanup
    ioctl(loopFd, LOOP_CLR_FD, 0);
    close(imgFd);
    close(loopFd);
    close(loopCtrlFd);

    return 0;
}
