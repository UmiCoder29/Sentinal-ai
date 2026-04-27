from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import List, Dict, Any

console = Console()

def generate_report(vulnerabilities: List[Dict[str, Any]]):
    if not vulnerabilities:
        console.print("[bold green]No SQL injection vulnerabilities detected![/bold green]")
        return

    console.print(Panel("[bold red]SQL Injection Vulnerability Report[/bold red]", expand=False))

    table = Table(title="Detected Vulnerabilities")
    table.add_column("Severity", justify="center")
    table.add_column("Location", justify="left")
    table.add_column("Reason", justify="left")
    table.add_column("Remediation", justify="left")

    severity_colors = {
        "Critical": "bold magenta",
        "High": "bold red",
        "Medium": "bold yellow",
        "Low": "bold blue"
    }

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Medium")
        color = severity_colors.get(severity, "white")
        
        table.add_row(
            f"[{color}]{severity}[/{color}]",
            f"{vuln['file']}:{vuln['line']}",
            vuln['reason'],
            vuln.get('remediation', 'N/A')
        )

    console.print(table)

    # Detailed view
    console.print("\n[bold]Detailed Findings:[/bold]")
    for i, vuln in enumerate(vulnerabilities, 1):
        severity = vuln.get("severity", "Medium")
        color = severity_colors.get(severity, "white")
        
        console.print(f"\n[bold]{i}. {vuln['file']}:{vuln['line']}[/bold]")
        console.print(f"  [bold]Code:[/bold] [dim]{vuln['code']}[/dim]")
        console.print(f"  [bold]Severity:[/bold] [{color}]{severity}[/{color}]")
        console.print(f"  [bold]Explanation:[/bold] {vuln.get('explanation', 'N/A')}")
        console.print(f"  [bold]Remediation:[/bold] [green]{vuln.get('remediation', 'N/A')}[/green]")
