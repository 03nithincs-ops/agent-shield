"""Local server launcher for AGENT SHIELD."""
from __future__ import annotations

import uvicorn


def main() -> None:
    print("Starting AGENT SHIELD Runtime Security Gateway at http://127.0.0.1:8000 ...")
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)


if __name__ == "__main__":
    main()
