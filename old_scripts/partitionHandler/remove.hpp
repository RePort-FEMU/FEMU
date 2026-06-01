#ifndef REMOVE_HPP
#define REMOVE_HPP

#include <sys/mount.h>

#include "util.hpp"

int removePartition(const std::string& path);

#endif // REMOVE_HPP