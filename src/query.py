import pandas as pd
try:
    from .loader import MitreLoader
except ImportError:
    from loader import MitreLoader

class MitreQuery:
    def __init__(self):
        self.loader = MitreLoader()
        self.df = self.loader.parse_data()

    def search_by_keyword(self, keyword):
        """Searches for techniques containing the keyword in name or description."""
        keyword = keyword.lower()
        mask = self.df.apply(lambda x: keyword in x['name'].lower() or keyword in x['description'].lower(), axis=1)
        return self.df[mask]

    def filter_by_datasource(self, datasource):
        """Filters techniques by data source."""
        datasource = datasource.lower()
        # Handle cases where data_sources might be None or empty
        # data_sources is a comma-separated string
        mask = self.df['data_sources'].apply(lambda x: datasource in x.lower() if isinstance(x, str) else False)
        return self.df[mask]

    def filter_by_tactic(self, tactic):
        """Filters techniques by tactic."""
        tactic = tactic.lower().replace(" ", "-")
        mask = self.df['tactics'].apply(lambda x: any(tactic in t.lower().replace(" ", "-") for t in x) if isinstance(x, list) else False)
        return self.df[mask]

    def filter_by_platform(self, platform):
        """Filters techniques by platform."""
        platform = platform.lower()
        mask = self.df['platforms'].apply(lambda x: any(platform in p.lower() for p in x) if isinstance(x, list) else False)
        return self.df[mask]

    def filter_by_threat_actor(self, actor_name):
        """Filters techniques used by a specific Threat Actor."""
        actor_name = actor_name.lower()
        mask = self.df['threat_actors'].apply(lambda x: any(actor_name in a.lower() for a in x) if isinstance(x, list) else False)
        return self.df[mask]

    def get_all_threat_actors(self):
        """Returns a list of all unique Threat Actors."""
        all_actors = set()
        for actors in self.df['threat_actors']:
            if isinstance(actors, list):
                for actor in actors:
                    all_actors.add(actor)
        return sorted(list(all_actors))

    def get_technique_details(self, technique_id):
        """Gets details for a specific technique ID (e.g., T1003)."""
        # Support both T1003 and T1003.001
        result = self.df[self.df['external_id'] == technique_id]
        if result.empty:
            return None
        return result.iloc[0].to_dict()

    def get_all_datasources(self):
        """Returns a list of all unique data sources."""
        all_sources = set()
        for sources in self.df['data_sources']:
            if isinstance(sources, str) and sources:
                for source in sources.split(", "):
                    all_sources.add(source)
        return sorted(list(all_sources))

    def get_all_tactics(self):
        """Returns a list of all unique tactics."""
        all_tactics = set()
        for tactics in self.df['tactics']:
            if isinstance(tactics, list):
                for tactic in tactics:
                    all_tactics.add(tactic)
        return sorted(list(all_tactics))
