import requests
import pandas as pd
import json
import os
from stix2 import MemoryStore, Filter

class MitreLoader:
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        self.enterprise_attack_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        self.local_file = os.path.join(self.data_dir, "enterprise-attack.json")
        
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

    def download_data(self, force=False):
        """Downloads the latest enterprise-attack.json if not present or forced."""
        if os.path.exists(self.local_file) and not force:
            print(f"Using cached data from {self.local_file}")
            return

        print(f"Downloading data from {self.enterprise_attack_url}...")
        response = requests.get(self.enterprise_attack_url)
        response.raise_for_status()
        
        with open(self.local_file, 'wb') as f:
            f.write(response.content)
        print("Download complete.")

    def parse_data(self):
        """Parses the STIX data into a Pandas DataFrame."""
        if not os.path.exists(self.local_file):
            self.download_data()

        print("Loading STIX data...")
        mem = MemoryStore()
        mem.load_from_file(self.local_file)

        # Get all techniques
        techniques = mem.query([
            Filter("type", "=", "attack-pattern")
        ])

        # ATT&CK v18 Data Source Extraction
        # In v18, the structure is: Technique <- Detection Strategy <- Analytics <- Log Source References
        # Log sources now live directly on Analytics via x_mitre_log_source_references
        # Each log source reference contains: x_mitre_data_component_ref, name, and channel
        
        # Get all Analytics and extract Data Component names from log source references
        analytics = mem.query([
            Filter("type", "=", "x-mitre-analytic")
        ])
        
        # Map Analytic ID to set of Data Component names (extracted from log sources)
        analytic_to_data_components = {}
        for a in analytics:
            log_refs = a.get("x_mitre_log_source_references", [])
            if log_refs:
                dc_names = set()
                for log_ref in log_refs:
                    dc_ref = log_ref.get("x_mitre_data_component_ref")
                    if dc_ref:
                        dc = mem.get(dc_ref)
                        if dc:
                            dc_names.add(dc["name"])
                if dc_names:
                    analytic_to_data_components[a["id"]] = dc_names

        # Get all detection strategies and map to Data Components via Analytics
        det_strategies = mem.query([
            Filter("type", "=", "x-mitre-detection-strategy")
        ])
        strat_to_data_components = {}
        for ds in det_strategies:
            analytic_refs = ds.get("x_mitre_analytic_refs", [])
            for ref in analytic_refs:
                if ref in analytic_to_data_components:
                    if ds["id"] not in strat_to_data_components:
                        strat_to_data_components[ds["id"]] = set()
                    strat_to_data_components[ds["id"]].update(analytic_to_data_components[ref])

        # Get relationships for detection strategies (detects)
        ds_relationships = mem.query([
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", "detects")
        ])

        # Map technique ID to list of Data Component names
        tech_to_data_components = {}
        for r in ds_relationships:
            if r["source_ref"] in strat_to_data_components and r["target_ref"].startswith("attack-pattern--"):
                if r["target_ref"] not in tech_to_data_components:
                    tech_to_data_components[r["target_ref"]] = set()
                tech_to_data_components[r["target_ref"]].update(strat_to_data_components[r["source_ref"]])
        
        # Get all intrusion sets (Threat Actors)
        intrusion_sets = mem.query([
            Filter("type", "=", "intrusion-set")
        ])
        
        # Create a map of ID to Name for intrusion sets
        intrusion_set_map = {i["id"]: i["name"] for i in intrusion_sets}

        # Get all relationships
        relationships = mem.query([
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", "uses")
        ])

        # Map technique ID to list of intrusion set names
        tech_to_actors = {}
        for r in relationships:
            if r["source_ref"] in intrusion_set_map and r["target_ref"].startswith("attack-pattern--"):
                if r["target_ref"] not in tech_to_actors:
                    tech_to_actors[r["target_ref"]] = []
                tech_to_actors[r["target_ref"]].append(intrusion_set_map[r["source_ref"]])

        data = []
        for t in techniques:
            # Skip deprecated or revoked
            if t.get("x_mitre_deprecated") or t.get("revoked"):
                continue

            # Get external ID (e.g., T1003)
            external_id = next((ref["external_id"] for ref in t.get("external_references", []) if ref["source_name"] == "mitre-attack"), None)
            
            # Get Data Components (v18 approach)
            data_sources = ", ".join(sorted(tech_to_data_components.get(t["id"], set())))
            
            # Get platforms
            platforms = t.get("x_mitre_platforms", [])
            
            # Get tactics
            tactics = [phase["phase_name"] for phase in t.get("kill_chain_phases", []) if phase["kill_chain_name"] == "mitre-attack"]

            # Get threat actors
            threat_actors = tech_to_actors.get(t["id"], [])

            data.append({
                "id": t["id"],
                "name": t["name"],
                "description": t.get("description", ""),
                "external_id": external_id,
                "data_sources": data_sources,
                "platforms": platforms,
                "tactics": tactics,
                "threat_actors": sorted(threat_actors),
                "url": next((ref["url"] for ref in t.get("external_references", []) if ref["source_name"] == "mitre-attack"), "")
            })

        df = pd.DataFrame(data)
        return df

if __name__ == "__main__":
    loader = MitreLoader()
    loader.download_data()
    df = loader.parse_data()
    print(f"Loaded {len(df)} techniques.")
    print(df.head())
