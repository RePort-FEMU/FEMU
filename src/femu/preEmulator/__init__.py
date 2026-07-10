"""Pre-emulation probe: inject init, classify the network, verify reachability."""

from typing import TYPE_CHECKING

from .networkClassifier import classifyNetwork
from .emulationVerifier import verifyEmulation, makeNetworkMonitor

# `PreEmulator` is exposed lazily: preEmulator.py imports ..qemuInterface, which
# in turn imports .preEmulator.freezeDiagnostics — eagerly importing PreEmulator
# here would form a circular import at package-init time. PEP 562 __getattr__
# defers it until the attribute is actually accessed.
if TYPE_CHECKING:
    from .preEmulator import PreEmulator

__all__ = ["PreEmulator", "classifyNetwork", "verifyEmulation", "makeNetworkMonitor"]


def __getattr__(name: str):
    if name == "PreEmulator":
        from .preEmulator import PreEmulator
        return PreEmulator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
