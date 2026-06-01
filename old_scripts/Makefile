
all: build addPartition mountPartition unmountimg

# If the build directory does not exist, create it
build:
	mkdir -p build

addPartition: build
	g++ -o build/addPartition addPartition.cpp

mountPartition: build
	g++ -o build/mountPartition mountPartition.cpp

unmountimg: build
	g++ -o build/umountImg umountImg.cpp

PHONY clean:
	rm -f build/*