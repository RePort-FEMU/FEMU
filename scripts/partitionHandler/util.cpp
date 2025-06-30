#include "util.hpp"

using namespace std;

int getAbsPath(const string& path, string& absPath) {
    char _absPath[PATH_MAX];
    if (path[0] != '/') {
        if (!realpath(path.c_str(), _absPath)) {
            perror("Failed to resolve absolute path");
            return -1;
        }
        absPath = _absPath;
    }
    else {
        absPath = path;
    }
    return 0;
}

int getFreeLoopDevice() {
    int loopCtrlFd = open("/dev/loop-control", O_RDWR);
    if (loopCtrlFd < 0) {
        perror("Failed to open /dev/loop-control");
        return -1;
    }

    int loopDevice = ioctl(loopCtrlFd, LOOP_CTL_GET_FREE);
    if (loopDevice < 0) {
        perror("Failed to get free loop device");
        close(loopCtrlFd);
        return -1;
    }
    close(loopCtrlFd);

    return loopDevice;
}

int fileAccessCheck(const string& filePath) {
    if (access(filePath.c_str(), F_OK) != 0) {
        std::cerr << "Error: File " << filePath << " does not exist." << std::endl;
        return -1;
    }
    if (access(filePath.c_str(), R_OK | W_OK) != 0) {
        std::cerr << "Error: File " << filePath << " is not readable or writable." << std::endl;
        return -1;
    }
    return 0;
}

int findLoopDevice(const string& path, string& loopDevice) {
    // Assume input is a mount point, try to find the backing loop device
    FILE *mnt = setmntent("/proc/mounts", "r");
    if (!mnt) {
        perror("Failed to open /proc/mounts");
        return -1;
    }

    struct mntent *ent;
    bool found = false;
    while ((ent = getmntent(mnt)) != nullptr) {
        if (strcmp(ent->mnt_dir, path.c_str()) == 0) {
            loopDevice = ent->mnt_fsname;
            found = true;
            break;
        }
    }
    endmntent(mnt);
    if (!found) {
        std::cerr << "Could not find loop device for mount point: " << path << std::endl;
        return -1; 
    }
    return 0;
}

int isLoopDevice(const string& path, bool& isLoopDevice) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0 && S_ISBLK(st.st_mode)) {
        // Input is a block device (loop device)
        isLoopDevice = true;
    } else {
        // Assume input is a mount point, try to find the backing loop device
        isLoopDevice = false;
    }
    return 0;
}

int isLoopMounted(const string& loopDevice, bool& isMounted) {
    struct stat st;
    if (stat(loopDevice.c_str(), &st) == 0 && S_ISBLK(st.st_mode)) {
        // Check if the loop device is mounted
        FILE *mnt = setmntent("/proc/mounts", "r");
        if (!mnt) {
            perror("Failed to open /proc/mounts");
            return -1; 
        }

        struct mntent *ent;
        while ((ent = getmntent(mnt)) != nullptr) {
            if (strcmp(ent->mnt_fsname, loopDevice.c_str()) == 0) {
                endmntent(mnt);
                isMounted = true; // Loop device is mounted
                return 0;
            }
        }
        endmntent(mnt);
    }
    isMounted = false; // Loop device is not mounted
    return 0;
}