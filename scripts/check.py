#!/usr/bin/env python3
"""Local, dependency-free tests. Never connects to a network or reads key stores."""
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parents[1]
result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'], cwd=root)
raise SystemExit(result.returncode)
