#ifndef UTIL_HPP
#define UTIL_HPP

#include <string>
#include <iostream>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/loop.h>
#include <mntent.h>
#include <string.h>
#include <sys/stat.h>

int getAbsPath(const std::string& path, std::string& absPath);
int getFreeLoopDevice();
int fileAccessCheck(const std::string& filePath);
int findLoopDevice(const std::string& path, std::string& loopDevice);
int isLoopDevice(const std::string& loopDevice, bool& isLoopDevice);
int isLoopMounted(const std::string& loopDevice, bool& isMounted);

#endif // UTIL_HPP