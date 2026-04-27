import argparse
import os
import sys
from sql_scanner.scanner import scan_directory
from sql_scanner.reporter import generate_report, console

def main():
    parser = argparse.ArgumentParser(description="Offline SQL Injection Scanner")
    parser.add_argument("path", help="Path to the codebase to scan", default=".", nargs="?")
    
    args = parser.parse_args()

    target_path = os.path.abspath(args.path)
    if not os.path.exists(target_path):
        console.print(f"[bold red]Error:[/bold red] Path '{target_path}' does not exist.")
        sys.exit(1)

    console.print(f"[bold blue]Scanning:[/bold blue] {target_path}")
    
    # 1. Scan for potential vulnerabilities
    vulnerabilities = scan_directory(target_path)
    
    if not vulnerabilities:
        console.print("[bold green]No potential SQL injection vulnerabilities found.[/bold green]")
        return

    # 2. Generate Report (Vulnerabilities already contain analysis data)
    generate_report(vulnerabilities)

if __name__ == "__main__":
    main()
