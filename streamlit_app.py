import streamlit as st
import sys
import os

# Ensure the project root is in sys.path
sys.path.append(os.path.dirname(__file__))

from src.app import main

if __name__ == "__main__":
    main()
