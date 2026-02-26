"""
Common test utilities - handles import paths for tests
"""
import sys
from pathlib import Path

# Add mvar-core directory to path so modules can be imported directly
MVAR_CORE_PATH = Path(__file__).parent.parent / "mvar-core"
if str(MVAR_CORE_PATH) not in sys.path:
    sys.path.insert(0, str(MVAR_CORE_PATH))
