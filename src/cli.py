import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown
from .query import MitreQuery

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
    parser = argparse.ArgumentParser(description="MitreHunter: Query MITRE ATT&CK TTPs")
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
import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown
from .query import MitreQuery
from .loader import MitreLoader # Assuming MitreLoader is in the same package

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
    parser = argparse.ArgumentParser(description="MitreHunter: Query MITRE ATT&CK TTPs")
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

    # List Data Sources command
    subparsers.add_parser("datasources", help="List all available data sources")

    # Sigma command
    sigma_parser = subparsers.add_parser("sigma", help="Manage Sigma rules")
    sigma_subparsers = sigma_parser.add_subparsers(dest="sigma_command", help="Sigma command")
    sigma_subparsers.add_parser("update", help="Download or update Sigma rules")

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
            
        details = query.get_technique_details(args.id)
        if details:
            console.print(f"[bold cyan]ID:[/bold cyan] {details['external_id']}")
            console.print(f"[bold magenta]Name:[/bold magenta] {details['name']}")
            console.print(f"[bold blue]Tactics:[/bold blue] {', '.join(details['tactics'])}")
            console.print(f"[bold green]Data Sources:[/bold green] {', '.join(details['data_sources'])}")
            console.print(f"[bold white]Platforms:[/bold white] {', '.join(details['platforms'])}")
            console.print(f"[bold red]Threat Actors:[/bold red] {', '.join(details.get('threat_actors', []))}")
            console.print(f"[bold]URL:[/bold] {details['url']}")
            console.print("\n[bold]Description:[/bold]")
            console.print(Markdown(details['description']))

            # Display Sigma Rules
            sigma_rules = query.get_sigma_rules_for_technique(args.id)
            if sigma_rules:
                console.print(f"\n[bold green]Sigma Rules ({len(sigma_rules)}):[/bold green]")
                for rule in sigma_rules:
                    console.print(f"  - {rule['title']} ([dim]{rule['level']}[/dim])")
            else:
                console.print("\n[dim]No Sigma rules found for this technique.[/dim]")
        else:
            console.print(f"[red]Technique {args.id} not found.[/red]")

    elif args.command == "datasources":
        with console.status("[bold green]Loading data...[/bold green]", spinner="dots"):
            query = MitreQuery()
        sources = query.get_all_datasources()
        console.print(f"[bold green]Available Data Sources ({len(sources)}):[/bold green]")
        for source in sources:
            console.print(f"  - {source}")

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
