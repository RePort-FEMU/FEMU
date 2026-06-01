#include "remove.hpp"

using namespace std;

int removeLoopDevice(const string& loopDevice) {
    bool isMounted = false;
    if(isLoopMounted(loopDevice, isMounted) < 0) {
        cerr << "Error: Could not determine if loop device is mounted: " << loopDevice << endl;
        return -1; // Error checking if loop device is mounted
    }

    if (isMounted)
        if(umount(loopDevice.c_str()) < 0) {
            perror("Failed to unmount loop device");
            return -1; // Error unmounting loop device
        }
    
    string nonPartitionPath;
    size_t pos = loopDevice.find_last_of('p');
    if (pos != string::npos && pos > 0 && isdigit(loopDevice[pos + 1])) {
        // Check if the part before 'p' is a loop device (e.g., /dev/loop0p1)
        string base = loopDevice.substr(0, pos);
        // Confirm base ends with a digit (e.g., /dev/loop0)
        if (!base.empty() && isdigit(base.back())) {
            nonPartitionPath = base;
        } else {
            nonPartitionPath = loopDevice;
        }
    } else {
        nonPartitionPath = loopDevice;
    }

    int loopFd = open(nonPartitionPath.c_str(), O_RDWR);
    if (loopFd < 0) {
        perror("Failed to open loop device");
        return -1; // Error opening loop device
    }

    if (ioctl(loopFd, LOOP_CLR_FD, 0) < 0) {
        perror("Failed to clear loop device file descriptor");
        close(loopFd);
        return -1; // Error clearing loop device
    }

    close(loopFd);
    std::cout << "Successfully removed loop device: " << loopDevice << std::endl;
    return 0; // Success
}

int removeMountpoint(const string& path) {
    // Find associated loop device
    string loopDevice;
    if (findLoopDevice(path, loopDevice) != 0) {
        cerr << "Error: Could not find loop device for mount point: " << path << endl;
        return -1; // Error finding loop device
    }

    if(removeLoopDevice(loopDevice) < 0) {
        cerr << "Error: Could not remove loop device: " << loopDevice << endl;
        return -1; // Error removing loop device
    }

    std::cout << "Successfully removed mount point: " << path << std::endl;
    return 0; // Success
}

int removePartition(const string& path) {
    if (fileAccessCheck(path) != 0) {
        return -1; // File does not exist or is not accessible
    }

    bool loopDeviceFlag = false;
    if(isLoopDevice(path, loopDeviceFlag) != 0) {
        cerr << "Error: Could not determine if path is a loop device: " << path << endl;
        return -1; // Error determining if path is a loop device
    }

    if(loopDeviceFlag)
        return removeLoopDevice(path); // If it's a loop device, remove it
    else 
        return removeMountpoint(path); // Otherwise, remove and unmount the partition
}