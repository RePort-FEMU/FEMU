
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/loop.h>
#include <sys/stat.h>
#include <cstring>
#include <stdexcept>
#include <string>    
#include <limits.h>
#include <mntent.h>
#include <sys/mount.h>

#include "util.hpp" 
#include "add.hpp"
#include "remove.hpp"

using namespace std;

enum class PartitionAction {
    Add,
    Remove,
    Mount,
    Umount
};

void showHelp() {
    std::cout << "Usage: partitionHandler <action> [options]" << std::endl;
    std::cout << "Actions:" << std::endl;
    std::cout << "  -a, --add    <rawImageFile>                 Create loop device" << std::endl;
    std::cout << "  -r, --remove <loopDevice>                   Remove loop device" << std::endl;
    std::cout << "               <mountPoint>                   Remove loop device and assosieted with mountPoint after unmounting it" << std::endl;
    std::cout << "  -m, --mount  <loopDevice>   <mountPoint>    Mount the first partition of the loop device" << std::endl;
    std::cout << "               <rawImageFile> <mountPoint>    Create loop device and mount it" << std::endl;
    std::cout << "  -u, --umount <mountPoint>                   Unmount a partition" << std::endl;
    std::cout << "  -h, --help                                  Show this help message" << std::endl;
}

int getArgs(int argc, char* argv[], PartitionAction& action, string fileArg[]) {
    if (argc < 3) {
        showHelp();
        return 1;
    }

    string actionStr = argv[1];
    if (actionStr == "-a" || actionStr == "--add") {
        action = PartitionAction::Add;
        if (argc != 3) {
            std::cerr << "Error: Invalid number of arguments for add action." << std::endl;
            showHelp();
            return 1;
        }
        if (getAbsPath(argv[2], fileArg[0]) != 0) return 1; // rawImageFile
    } else if (actionStr == "-r" || actionStr == "--remove") {
        action = PartitionAction::Remove;
        if (argc != 3) {
            std::cerr << "Error: Invalid number of arguments for remove action." << std::endl;
            showHelp();
            return 1;
        }
        if (getAbsPath(argv[2], fileArg[0]) != 0) return 1; // loopDevice or mountPoint
    } else if (actionStr == "-m" || actionStr == "--mount") {
        action = PartitionAction::Mount;
        if (argc != 4) {
            std::cerr << "Error: Invalid number of arguments for mount action." << std::endl;
            showHelp();
            return 1;
        }
        if (getAbsPath(argv[2], fileArg[0]) != 0) return 1; // loopDevice or rawImageFile
        if (getAbsPath(argv[3], fileArg[1]) != 0) return 1; // mountPoint
    } else if (actionStr == "-u" || actionStr == "--umount") {
        action = PartitionAction::Umount;
        if (argc != 3) {
            std::cerr << "Error: Invalid number of arguments for umount action." << std::endl;
            showHelp();
            return 1;
        }
        if (getAbsPath(argv[2], fileArg[0]) != 0) return 1; // mountPoint
    } else if (actionStr == "-h" || actionStr == "--help") {
        showHelp();
    } else {
        std::cerr << "Error: Unknown action '" << actionStr << "'." << std::endl;
        showHelp();
        return 1;
    }
    
    return 0;
}

int mountPartition(const string& loopDevice, const string& mountPoint) {
    if (mkdir(mountPoint.c_str(), 0755) < 0 && errno != EEXIST) {
        perror("Failed to create mount point directory");
        return -1; 
    }

    
}

int main(int argc, char* argv[])
{
    if (geteuid() != 0) {
        std::cerr << "This program must be run as root." << std::endl;
        return 1;
    }

    PartitionAction action;
    string* paths = new string[argc - 2]; // Allocate array for paths

    if(getArgs(argc, argv, action, paths) != 0) {
        delete[] paths; // Clean up allocated memory
        return 1;
    }

    int result = 0;
    switch (action) {
        case PartitionAction::Add: {
            result = addPartition(paths[0]);
            break;
        }
        case PartitionAction::Remove: {
            result = removePartition(paths[0]);
            break;
        }
        case PartitionAction::Mount: {
            // Call mountPartition function
            std::cout << "Mounting partition from loop device or image file: " << paths[0] << " to mount point: " << paths[1] << std::endl;
            // Implement mountPartition logic here
            break;
        }
        case PartitionAction::Umount: {
            // Call umountImg function
            std::cout << "Unmounting partition at mount point: " << paths[0] << std::endl;
            // Implement umountImg logic here
            break;
        }
    }
}