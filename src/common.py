from enum import Enum

class RunningMode(Enum):
    RUN = "run"
    CHECK = "check"
    ANALYZE = "analyze"
    DEBUG = "debug"
    def __str__(self):
        return self.value