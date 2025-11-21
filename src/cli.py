import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown
try:
    from .loader import MitreLoader
    from .loader import MitreLoader
    from .query import MitreQuery
    from . import __version__
except ImportError:
    from loader import MitreLoader
    from query import MitreQuery
    __version__ = "1.3.0"
import json
import yaml
import csv

console = Console()

def print_techniques(techniques, title="Techniques"):
    if techniques.empty:
        console.print(f"[yellow]No techniques found for {title}.[/yellow]")
        return

    table = Table(title=title)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("Data Sources", style="green")
    table.add_column("Tactics", style="blue")
    table.add_column("Threat Actors", style="red")

    for _, row in techniques.iterrows():
        ds = ", ".join(row['data_sources']) if isinstance(row['data_sources'], list) else ""
        tactics = ", ".join(row['tactics']) if isinstance(row['tactics'], list) else ""
        actors = ", ".join(row['threat_actors']) if isinstance(row.get('threat_actors'), list) else ""
        table.add_row(row['external_id'], row['name'], ds, tactics, actors)

    console.print(table)

def main():
    parser = argparse.ArgumentParser(description=f"MitreHunter v{__version__}: Query MITRE ATT&CK TTPs")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Update command
    subparsers.add_parser("update", help="Download latest MITRE ATT&CK data")

    # Search command
    search_parser = subparsers.add_parser("search", help="Search techniques by keyword")
    search_parser.add_argument("keyword", help="Keyword to search for")

    # Hunt command
    hunt_parser = subparsers.add_parser("hunt", help="Find techniques by data source")
    hunt_parser.add_argument("--datasource", required=True, help="Data source to filter by (e.g., 'Process Monitoring')")

    # Actor command
    actor_parser = subparsers.add_parser("actor", help="Find techniques by Threat Actor")
    actor_parser.add_argument("name", help="Threat Actor name (e.g., 'APT29')")

    # Info command
    info_parser = subparsers.add_parser("info", help="Get details for a specific technique")
    info_parser.add_argument("id", help="Technique ID (e.g., T1003)")
    info_parser.add_argument("--export", choices=['json', 'csv', 'yaml'], help="Export Sigma queries to a file")

    # List Data Sources command
    subparsers.add_parser("datasources", help="List all available data sources")

    args = parser.parse_args()

    if args.command == "update":
        with console.status("[bold green]Updating MITRE ATT&CK data...[/bold green]", spinner="dots"):
            query = MitreQuery()
            query.loader.download_data(force=True)
            query.loader.parse_data()
        console.print("[bold green]Update complete.[/bold green]")

    elif args.command == "search":
        with console.status("[bold green]Loading data...[/bold green]", spinner="dots"):
            query = MitreQuery()
        results = query.search_by_keyword(args.keyword)
        print_techniques(results, f"Search Results for '{args.keyword}'")

    elif args.command == "hunt":
        with console.status("[bold green]Loading data...[/bold green]", spinner="dots"):
            query = MitreQuery()
        results = query.filter_by_datasource(args.datasource)
        print_techniques(results, f"Techniques for Data Source: '{args.datasource}'")

    elif args.command == "actor":
        with console.status("[bold green]Loading data...[/bold green]", spinner="dots"):
            query = MitreQuery()
        results = query.filter_by_threat_actor(args.name)
        print_techniques(results, f"Techniques for Threat Actor: '{args.name}'")

    elif args.command == "info":
        with console.status("[bold green]Loading data...[/bold green]", spinner="dots"):
            # Load MITRE data
            query = MitreQuery()
            
            # Load Sigma rules (cached)
            console.log("Loading Sigma rules...")
            loader = MitreLoader()
            sigma_rules = loader.parse_sigma_rules()
            query.sigma_rules = sigma_rules
            
            # Initialize converter
            try:
                from .converter import SigmaConverter
                converter = SigmaConverter()
            except ImportError:
                from converter import SigmaConverter
                converter = SigmaConverter()
            
        details = query.get_technique_details(args.id)
        if details:
            console.print(f"[bold cyan]ID:[/bold cyan] {details['external_id']}")
            console.print(f"[bold cyan]Name:[/bold cyan] {details['name']}")
            console.print(f"[bold cyan]Description:[/bold cyan] {details['description'][:200]}...")
            console.print(f"[bold cyan]URL:[/bold cyan] {details['url']}")
            console.print(f"[bold cyan]Data Sources:[/bold cyan] {details['data_sources']}")
            
            # Sigma Rules
            sigma_rules = query.get_sigma_rules_for_technique(args.id)
            if sigma_rules:
                console.print(f"\n[bold green]Sigma Rules ({len(sigma_rules)}):[/bold green]")
                
                export_data = []
                
                for rule in sigma_rules:
                    console.print(f"- {rule['title']} ({rule['level']})")
                    
                    # Read raw YAML
                    try:
                        with open(rule['path'], 'r', encoding='utf-8') as f:
                            raw_yaml = f.read()
                    except Exception:
                        raw_yaml = ""
                    
                    # Convert
                    queries = converter.convert_to_all(raw_yaml)
                    
                    # Add to export list
                    export_data.append({
                        "title": rule['title'],
                        "id": rule['id'],
                        "splunk": queries['splunk'],
                        "crowdstrike": queries['crowdstrike']
                    })
                    
                    # Display queries in CLI (truncated for readability)
                    console.print(f"  [dim]Splunk:[/dim] {queries['splunk'][:100]}...")
                    console.print(f"  [dim]CrowdStrike:[/dim] {queries['crowdstrike'][:100]}...")

                # Handle Export
                if args.export:
                    filename = f"{args.id}_sigma_queries.{args.export}"
                    try:
                        if args.export == 'json':
                            import json
                            with open(filename, 'w', encoding='utf-8') as f:
                                json.dump(export_data, f, indent=2)
                        elif args.export == 'yaml':
                            import yaml
                            with open(filename, 'w', encoding='utf-8') as f:
                                yaml.dump(export_data, f, sort_keys=False)
                        elif args.export == 'csv':
                            import csv
                            with open(filename, 'w', newline='', encoding='utf-8') as f:
                                writer = csv.DictWriter(f, fieldnames=["title", "id", "splunk", "crowdstrike"])
                                writer.writeheader()
                                writer.writerows(export_data)
                        
                        console.print(f"\n[bold green]Successfully exported queries to {filename}[/bold green]")
                    except Exception as e:
                        console.print(f"\n[bold red]Export failed: {e}[/bold red]")
            else:
                console.print("\n[yellow]No Sigma rules found.[/yellow]")
        else:
            console.print(f"[bold red]Technique {args.id} not found.[/bold red]")

    elif args.command == "sigma":
        if args.sigma_command == "update":
            with console.status("[bold green]Updating Sigma rules...[/bold green]", spinner="dots"):
                loader = MitreLoader()
                loader.download_sigma_rules()
            console.print("[bold green]Sigma rules updated successfully![/bold green]")
        else:
            parser.print_help() # Or sigma_parser.print_help()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
