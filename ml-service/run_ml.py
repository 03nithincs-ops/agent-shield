"""
Launcher for Agent Shield Python ML Service
"""
import uvicorn
import os
import sys

# Ensure current directory is on python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    print("=======================================================")
    print("  AGENT SHIELD ISOLATION FOREST ML SERVICE             ")
    print("  FastAPI Server: http://127.0.0.1:8001                ")
    print("  Docs / OpenAPI: http://127.0.0.1:8001/docs           ")
    print("=======================================================")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8001, reload=False, log_level="info")

if __name__ == "__main__":
    main()
