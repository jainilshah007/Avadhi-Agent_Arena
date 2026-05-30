"""Allow running as `python -m avadhi`."""
import sys

from avadhi.cli import app

try:
    app()
except KeyboardInterrupt:
    print("\nInterrupted by user")
    sys.exit(130)
except Exception as e:
    print(f"Fatal error: {e}", file=sys.stderr)
    sys.exit(1)
