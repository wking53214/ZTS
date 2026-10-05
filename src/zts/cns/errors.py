class CNSDockError(Exception):
    """Base exception for CNS docking failures."""


class CNSUnavailableError(CNSDockError):
    """Raised when the CNS contract cannot be imported or reached."""


class CNSContractError(CNSDockError):
    """Raised when the available CNS contract is incompatible."""


class CNSVerificationError(CNSDockError):
    """Raised when a docked artifact fails integrity verification."""
