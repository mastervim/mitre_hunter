import os
import sys
import subprocess
import time

def print_step(message):
    print(f"[*] {message}")

def check_dependencies():
    print_step("Checking dependencies...")
    try:
        import streamlit
        import pandas
        import rich
        import stix2
        print_step("All dependencies found.")
        return True
    except ImportError as e:
        print(f"[!] Missing dependency: {e.name}")
        return False

def install_dependencies():
    print_step("Installing dependencies from requirements.txt...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print_step("Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("[!] Failed to install dependencies. Please run 'pip install -r requirements.txt' manually.")
        return False

def run_app():
    print_step("Launching MitreHunter Web Interface...")
    print_step("Press Ctrl+C to stop the server.")
    time.sleep(1)
    
    # Get the path to streamlit_app.py
    app_path = os.path.join(os.path.dirname(__file__), "streamlit_app.py")
    
    # Run streamlit
    try:
        subprocess.run([sys.executable, "-m", "streamlit", "run", app_path])
    except KeyboardInterrupt:
        print("\n[*] MitreHunter stopped.")

def main():
    print("="*50)
    try:
        from src import __version__
    except ImportError:
        __version__ = "1.3.0" # Fallback
    print(f"Welcome to MitreHunter v{__version__}")
    print("="*50)
    print("This script will set up the environment and launch the tool.\n")

    if not check_dependencies():
        choice = input("Would you like to install missing dependencies now? (y/n): ").lower()
        if choice == 'y':
            if not install_dependencies():
                return
        else:
            print("[!] Cannot proceed without dependencies.")
            return

    run_app()

if __name__ == "__main__":
    main()
