# conftest.py — pytest configuration for the Threat Pipeline project.
# Ensures the project root is on sys.path so `from src.* import ...` works.
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
