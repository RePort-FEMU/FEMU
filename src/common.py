from enum import Enum

class RunningMode(Enum):
    RUN = "run"
    CHECK = "check"
    ANALYZE = "analyze"
    DEBUG = "debug"
    def __str__(self):
        return self.value
    
class Architecture(Enum):
    MIPS= ("MIPS", "mips")
    MIPS64 = ("MIPS64","mips64")
    ARM = ("ARM", "arm")
    ARM64 = ("ARM64", "arm64")
    INTEL_80386 = ("INTEL_80386", "intel")
    X86_64 = ("X86_64", "intel64")
    POWERPC = ("POWERPC", "powerpc")
    UNKNOWN = ("UNKNOWN", "unknown")

    def __str__(self):
        return self.value[1]
    
    # Create a comparison method to check if two architectures are the same
    def __eq__(self, other):
        if isinstance(other, Architecture):
            return self.value[0] == other.value[0]
        return False
    
    def identifier(self):
        return self.value[0]

class Endianess(Enum):
    LITTLE = ("LSB", "el")
    BIG = ("MSB", "eb")
    UNKNOWN = ("UNKNOWN", "unknown")
    
    def __str__(self):
        return self.value[1]
    
    def identifier(self):
        return self.value[0]