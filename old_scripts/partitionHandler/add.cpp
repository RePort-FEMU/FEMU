#include "add.hpp"

using namespace std;

int createLoopDevice(const string& rawImageFile) {
    if(fileAccessCheck(rawImageFile) != 0) {
        return -1;
    }

    int loopDevice = getFreeLoopDevice();
    if (loopDevice < 0) {
        return -1;
    }

    std::string loopPath = "/dev/loop" + std::to_string(loopDevice);

    int loopFd, cnt = 0;
    do {
        errno = 0; // Reset errno before each attempt

        loopFd = open(loopPath.c_str(), O_RDWR);
        if (loopFd > 0)
            break; // Successfully opened the loop device

        /* We have permissions to open /dev/loop-control, but open
		 * /dev/loopN failed with EACCES, it's probably because udevd
		 * does not applied chown yet. Let's wait a moment. */
        if(errno != EACCES && errno != ENOENT) 
            break;
        usleep(25000);
    } while (cnt++ < 16);
    if (loopFd < 0) {
        perror("Failed to open loop device");
        return -1; 
    }

    int imgFd = open(rawImageFile.c_str(), O_RDWR);
    if (imgFd < 0) {
        perror("Failed to open image file");
        close(loopFd);
        return -1; 
    }

    struct loop_config lc;
    memset(&lc, 0, sizeof(lc));
    lc.fd = imgFd;
    strncpy(reinterpret_cast<char*>(lc.info.lo_file_name), rawImageFile.c_str(), LO_NAME_SIZE - 1);
    lc.info.lo_flags = LO_FLAGS_PARTSCAN;

    if (ioctl(loopFd, LOOP_CONFIGURE, &lc) < 0) {
        perror("Failed to configure loop device");
        ioctl(loopFd, LOOP_CLR_FD, 0);
        close(imgFd);
        close(loopFd);
        return -1; 
    }

    close(imgFd);
    close(loopFd);
    return loopDevice;
}

int addPartition(const string& rawImageFile){
    
    int loopDevice = createLoopDevice(rawImageFile);
    if (loopDevice < 0) {
        std::cerr << "Error: Could not create loop device for file: " << rawImageFile << std::endl;
        return -1;
    }

    std::cout << "Loop device created: " << "/dev/loop" << loopDevice << std::endl;
    return 0;
}