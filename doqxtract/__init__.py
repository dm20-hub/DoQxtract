"""DoQxtract, a flow feature extractor for DNS over QUIC (DoQ) traffic."""
from .extract import FEATURES, extract_records
from .scan import scan_capture

__version__ = "1.0.0"
__all__ = ["FEATURES", "extract_records", "scan_capture", "__version__"]
