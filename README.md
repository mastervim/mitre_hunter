# 🛡️ MitreHunter

**MitreHunter** is a powerful threat hunting tool designed to query and leverage MITRE ATT&CK TTPs efficiently. It focuses on filtering techniques by **Data Sources**, **Threat Actors**, **Tactics**, and **Platforms**.

## Features

- **Data Source Filtering**: Find techniques visible via specific logs (e.g., "Active Directory Object Access").
- **Threat Actor Tracking**: Identify techniques used by specific APT groups (e.g., "APT29").
- **CLI & Web Interface**: Use the command line for quick queries or the Streamlit web app for interactive exploration.
- **Live Data**: Fetches the latest enterprise-attack.json directly from MITRE's GitHub.
- **v18 Support**: Fully compatible with MITRE ATT&CK v18 data model (Log Sources on Analytics).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mastervim/mitre_hunter.git
   cd mitre_hunter
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### CLI

Run the CLI module:

```bash
# Update data
python -m src.cli update

# Get info on a technique
python -m src.cli info T1003

# Hunt by Data Source
python -m src.cli hunt --datasource "Process Creation"

# Find techniques by Threat Actor
python -m src.cli actor "APT29"

# List all Data Sources
python -m src.cli datasources
```

### Web Interface

Run the Streamlit app:

```bash
streamlit run src/app.py
```

## Project Structure

- `src/loader.py`: Handles downloading and parsing STIX data (implements v18 extraction logic).
- `src/query.py`: Core logic for filtering and searching.
- `src/cli.py`: Command-line interface.
- `src/app.py`: Streamlit web application.
- `data/`: Local cache for MITRE STIX data.
