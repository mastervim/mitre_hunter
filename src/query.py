import pandas as pd
from typing import Optional, List, Set, Dict, Any, Union
try:
    from .loader import MitreLoader
except ImportError:
    from loader import MitreLoader

# Security: Limit query results to prevent DoS attacks
MAX_RESULTS = 1000

class MitreQuery:
    """Handles querying and filtering of MITRE ATT&CK data."""
    def __init__(self, df: Optional[pd.DataFrame] = None):
        """Initialize the query engine.
        
        Args:
            df: Optional pre-loaded DataFrame. If None, loads data using MitreLoader.
        """
        self.loader = MitreLoader()
        if df is not None:
            self.df = df
        else:
            self.df = self.loader.parse_data()

    def search_by_keyword(self, keyword: str, max_results: int = MAX_RESULTS) -> pd.DataFrame:
        """Searches for techniques containing the keyword in name or description.
        
        Args:
            keyword: Search term.
            max_results: Maximum number of results to return (default: 1000).
            
        Returns:
            pd.DataFrame: Filtered DataFrame containing matching techniques.
        """
        keyword = keyword.lower()
        mask = self.df.apply(lambda x: keyword in x['name'].lower() or keyword in x['description'].lower(), axis=1)
        results = self.df[mask]
        if len(results) > max_results:
            print(f"[Security] Results truncated to {max_results} (found {len(results)})")
            return results.head(max_results)
        return results

    def filter_by_datasource(self, datasource: str, max_results: int = MAX_RESULTS) -> pd.DataFrame:
        """Filters techniques by data source.
        
        Args:
            datasource: Data source to filter by (e.g., "Process Creation").
            max_results: Maximum number of results to return (default: 1000).
            
        Returns:
            pd.DataFrame: Filtered DataFrame.
        """
        datasource = datasource.lower()
        # Handle cases where data_sources might be None or empty
        # data_sources is a comma-separated string
        mask = self.df['data_sources'].apply(lambda x: datasource in x.lower() if isinstance(x, str) else False)
        results = self.df[mask]
        if len(results) > max_results:
            print(f"[Security] Results truncated to {max_results} (found {len(results)})")
            return results.head(max_results)
        return results

    def filter_by_tactic(self, tactic: str) -> pd.DataFrame:
        """Filters techniques by tactic.
        
        Args:
            tactic: Tactic name (e.g., "Persistence").
            
        Returns:
            pd.DataFrame: Filtered DataFrame.
        """
        tactic = tactic.lower().replace(" ", "-")
        mask = self.df['tactics'].apply(lambda x: any(tactic in t.lower().replace(" ", "-") for t in x) if isinstance(x, list) else False)
        return self.df[mask]

    def filter_by_platform(self, platform: str) -> pd.DataFrame:
        """Filters techniques by platform.
        
        Args:
            platform: Platform name (e.g., "Windows").
            
        Returns:
            pd.DataFrame: Filtered DataFrame.
        """
        platform = platform.lower()
        mask = self.df['platforms'].apply(lambda x: any(platform in p.lower() for p in x) if isinstance(x, list) else False)
        return self.df[mask]

    def filter_by_threat_actor(self, actor_name: str) -> pd.DataFrame:
        """Filters techniques used by a specific Threat Actor.
        
        Args:
            actor_name: Threat Actor name (e.g., "APT29").
            
        Returns:
            pd.DataFrame: Filtered DataFrame.
        """
        actor_name = actor_name.lower()
        mask = self.df['threat_actors'].apply(lambda x: any(actor_name in a.lower() for a in x) if isinstance(x, list) else False)
        return self.df[mask]

    def get_all_threat_actors(self) -> List[str]:
        """Returns a list of all unique Threat Actors.
        
        Returns:
            List[str]: Sorted list of threat actor names.
        """
        all_actors = set()
        for actors in self.df['threat_actors']:
            if isinstance(actors, list):
                for actor in actors:
                    all_actors.add(actor)
        return sorted(list(all_actors))

    def get_technique_details(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Gets details for a specific technique ID (e.g., T1003).
        
        Args:
            technique_id: The external ID of the technique.
            
        Returns:
            Optional[Dict[str, Any]]: Dictionary of technique details, or None if not found.
        """
        # Support both T1003 and T1003.001
        result = self.df[self.df['external_id'] == technique_id]
        if result.empty:
            return None
        return result.iloc[0].to_dict()

    def get_all_datasources(self) -> List[str]:
        """Returns a list of all unique data sources.
        
        Returns:
            List[str]: Sorted list of data source names.
        """
        all_sources = set()
        for sources in self.df['data_sources']:
            if isinstance(sources, str) and sources:
                for source in sources.split(", "):
                    all_sources.add(source)
        return sorted(list(all_sources))

    def get_all_tactics(self) -> List[str]:
        """Returns a list of all unique tactics.
        
        Returns:
            List[str]: Sorted list of tactic names.
        """
        all_tactics = set()
        for tactics in self.df['tactics']:
            if isinstance(tactics, list):
                for tactic in tactics:
                    all_tactics.add(tactic)
        return sorted(list(all_tactics))
