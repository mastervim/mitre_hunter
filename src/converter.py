import logging
import yaml
from typing import Dict, Any, Optional
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.crowdstrike import LogScaleBackend

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SigmaConverter:
    """Handles conversion of Sigma rules to various target query languages."""
    
    def __init__(self):
        """Initialize the converter with backends."""
        try:
            self.splunk_backend = SplunkBackend()
            self.crowdstrike_backend = LogScaleBackend()
            self.backends_available = True
        except Exception as e:
            logger.error(f"Failed to initialize Sigma backends: {e}")
            self.backends_available = False

    def convert(self, rule_yaml: str, target: str) -> str:
        """Convert a raw Sigma YAML string to a target query language.
        
        Args:
            rule_yaml: The raw YAML content of the Sigma rule.
            target: The target language ('splunk' or 'crowdstrike').
            
        Returns:
            str: The generated query or an error message.
        """
        if not self.backends_available:
            return "Error: Sigma backends not initialized."
            
        try:
            # Parse the rule
            rules = SigmaCollection.from_yaml(rule_yaml)
            
            if target == 'splunk':
                queries = self.splunk_backend.convert(rules)
            elif target == 'crowdstrike':
                queries = self.crowdstrike_backend.convert(rules)
            else:
                return f"Error: Unknown target '{target}'"
                
            # Return the first query (usually one rule = one query)
            if queries:
                return queries[0]
            return "No query generated."
            
        except Exception as e:
            logger.warning(f"Conversion failed for target {target}: {e}")
            return f"Conversion Error: {str(e)}"

    def convert_to_all(self, rule_yaml: str) -> Dict[str, str]:
        """Convert a rule to all supported languages.
        
        Args:
            rule_yaml: The raw YAML content of the Sigma rule.
            
        Returns:
            Dict[str, str]: Dictionary mapping target names to generated queries.
        """
        return {
            "splunk": self.convert(rule_yaml, "splunk"),
            "crowdstrike": self.convert(rule_yaml, "crowdstrike")
        }
