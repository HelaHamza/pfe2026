"""Rend ML/ importable depuis les tests, quel que soit le cwd de pytest."""
import os
import sys

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)
