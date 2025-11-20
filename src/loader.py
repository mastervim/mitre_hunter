import requests
import pandas as pd
import json
import os
import hashlib
import warnings
import logging
import subprocess
import yaml
import json
import time
from typing import Optional, List, Set, Dict, Any
from stix2 import MemoryStore, Filter

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MitreLoader:
    """Handles downloading and parsing of MITRE ATT&CK STIX data."""
    
    def __init__(self, data_dir: str = "data"):
        """Initialize the loader.
        
        Args:
            data_dir: Directory to store cached STIX data.
        """
        self.data_dir = data_dir
        self.enterprise_attack_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        self.local_file = os.path.join(self.data_dir, "enterprise-attack.json")
        self.sigma_dir = os.path.join(self.data_dir, "sigma")
        self.sigma_cache_file = os.path.join(self.data_dir, "sigma_cache.json")
        self.sigma_repo_url = "https://github.com/SigmaHQ/sigma.git"
        
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

    def download_data(self, force: bool = False) -> None:
        """Downloads the latest enterprise-attack.json if not present or forced.
        
        Args:
            force: If True, force re-download even if file exists.
        """
        if os.path.exists(self.local_file) and not force:
            logger.info(f"Using cached data from {self.local_file}")
            return

        logger.info(f"Downloading data from {self.enterprise_attack_url}...")
        try:
            response = requests.get(self.enterprise_attack_url)
            response.raise_for_status()
            
            with open(self.local_file, 'wb') as f:
                f.write(response.content)
            logger.info("Download complete.")
        except requests.RequestException as e:
            logger.error(f"Failed to download data: {e}")
            raise
        
        # Security: Verify data integrity
        self._verify_data_integrity()
    
    def _verify_data_integrity(self):
        """Verifies the integrity of downloaded data using SHA256.
        
        Note: This is a basic integrity check. For production use, consider
        verifying against a known-good hash published by MITRE.
        """
        if not os.path.exists(self.local_file):
            return
        
        sha256_hash = hashlib.sha256()
        with open(self.local_file, 'rb') as f:
            # Read in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        file_hash = sha256_hash.hexdigest()
        file_size = os.path.getsize(self.local_file)
        
        print(f"[Security] Data integrity check:")
        print(f"  SHA256: {file_hash}")
        print(f"  Size: {file_size:,} bytes")
        
        # Warn if file seems suspiciously small (likely corrupted)
        if file_size < 1000000:  # Less than 1MB
            warnings.warn(
                f"Downloaded file is suspiciously small ({file_size} bytes). "
                "Data may be corrupted. Consider re-downloading with 'update' command.",
                UserWarning
            )

    def download_sigma_rules(self, force: bool = False) -> None:
        """Clones or updates the SigmaHQ/sigma repository.
        
        Args:
            force: If True, deletes existing directory and re-clones.
        """
        if os.path.exists(self.sigma_dir):
            if force:
                logger.info("Force updating Sigma rules (re-cloning)...")
                # Simple approach: remove dir and clone again
                # In production, might want to use shutil.rmtree, but let's rely on git for now or manual cleanup
                # For safety, we'll just try to pull if it exists, unless force is explicit
                pass 
            
            logger.info("Updating Sigma rules...")
            try:
                subprocess.run(["git", "-C", self.sigma_dir, "pull"], check=True, capture_output=True)
                logger.info("Sigma rules updated.")
                return
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to update Sigma rules: {e}. Trying re-clone.")
                # If pull fails, fall through to re-clone logic (requires clearing dir)
                import shutil
                shutil.rmtree(self.sigma_dir, ignore_errors=True)

        logger.info(f"Cloning Sigma rules from {self.sigma_repo_url}...")
        try:
            subprocess.run(["git", "clone", self.sigma_repo_url, self.sigma_dir], check=True, capture_output=True)
            logger.info("Sigma rules cloned.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to clone Sigma rules: {e}")
            # Don't raise, just log error so app can continue without Sigma
    
    def parse_sigma_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Parses Sigma rules and maps them to MITRE Technique IDs.
        
        Uses a JSON cache to avoid re-parsing thousands of YAML files if the
        directory hasn't changed.
        
        Returns:
            Dict[str, List[Dict]]: Map of Technique ID (e.g., 'T1003') to list of rule dicts.
        """
        if not os.path.exists(self.sigma_dir):
            logger.warning("Sigma rules directory not found. Skipping Sigma parsing.")
            return {}

        # Check cache
        if os.path.exists(self.sigma_cache_file):
            try:
                cache_mtime = os.path.getmtime(self.sigma_cache_file)
                sigma_mtime = os.path.getmtime(self.sigma_dir)
                # If cache is newer than the directory modification, use it
                # Note: git pull updates dir mtime
                if cache_mtime > sigma_mtime:
                    logger.info("Loading Sigma rules from cache...")
                    with open(self.sigma_cache_file, 'r', encoding='utf-8') as f:
                        return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load Sigma cache: {e}. Reparsing.")

        logger.info("Parsing Sigma rules (this may take a moment)...")
        technique_to_rules = {}
        rules_dir = os.path.join(self.sigma_dir, "rules")
        
        count = 0
        start_time = time.time()
        
        for root, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith(".yml"):
                    try:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8') as f:
                            # Use CLoader if available for speed
                            rule = yaml.load(f, Loader=Loader)
                            
                        if not rule or 'tags' not in rule:
                            continue
                            
                        # Extract MITRE tags (e.g., attack.t1003)
                        mitre_tags = [t for t in rule['tags'] if t.startswith('attack.t')]
                        
                        if mitre_tags:
                            rule_data = {
                                "title": rule.get("title", "Unknown Rule"),
                                "id": rule.get("id", ""),
                                "description": rule.get("description", ""),
                                "level": rule.get("level", "unknown"),
                                "tags": rule['tags'],
                                "path": file_path
                            }
                            
                            for tag in mitre_tags:
                                # Convert attack.t1003 -> T1003
                                tech_id = tag.split('.')[1].upper()
                                if tech_id not in technique_to_rules:
                                    technique_to_rules[tech_id] = []
                                technique_to_rules[tech_id].append(rule_data)
                            count += 1
                            
                    except Exception as e:
                        # Skip malformed files
                        continue
        
        elapsed = time.time() - start_time
        logger.info(f"Parsed {count} Sigma rules in {elapsed:.2f}s.")
        
        # Save to cache
        try:
            with open(self.sigma_cache_file, 'w', encoding='utf-8') as f:
                json.dump(technique_to_rules, f)
            logger.info("Sigma rules cached.")
        except Exception as e:
            logger.warning(f"Failed to cache Sigma rules: {e}")
            
        return technique_to_rules

    def parse_data(self) -> pd.DataFrame:
        """Parses the STIX data into a Pandas DataFrame.
        
        Returns:
            pd.DataFrame: DataFrame containing technique data.
        """
        if not os.path.exists(self.local_file):
            self.download_data()

        logger.info("Loading STIX data...")
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
