
all: build mountimg unmountimg

# If the build directory does not exist, create it
build:
	mkdir -p build

mountimg: build
	g++ -o build/mountImg mountImg.cpp

unmountimg: build
	g++ -o build/umountImg umountImg.cpp

PHONY clean:
	rm -f build/*