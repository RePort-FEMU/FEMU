#ifndef ADD_HPP
#define ADD_HPP
#include <unistd.h>

#include "util.hpp"

int createLoopDevice(const string& rawImageFile);
int addPartition(const string& rawImageFile);

#endif // ADD_HPP