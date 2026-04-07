"""CLI entry point: replay and verify every envelope in audit.jsonl."""

import json
import sys

from auths import verify_action_envelope
from rich.console import Console
from rich.table import Table

from single_agent.audit import load_agent_key, read_all

console = Console()


def main() -> None:
    try:
        key_info = load_agent_key()
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    pub_hex: str = key_info["public_key_hex"]
    did: str = key_info["did"]
    entries = read_all()

    if not entries:
        console.print("[yellow]No entries in audit.jsonl. Run `run-agent` first.[/yellow]")
        sys.exit(0)

    console.print("\n[bold]Verifying audit trail...[/bold]")
    console.print(f"Signer: [dim]{did}[/dim]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=4)
    table.add_column("Tool", min_width=20)
    table.add_column("Valid", width=8)
    table.add_column("Timestamp", min_width=20)

    passed = 0
    failed = 0

    for i, entry in enumerate(entries, 1):
        result = verify_action_envelope(json.dumps(entry), pub_hex)

        payload = entry.get("payload", {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}
        tool_name = (
            payload.get("tool")
            or entry.get("action_type")
            or entry.get("type")
            or "unknown"
        )

        timestamp = entry.get("timestamp", "")[:19].replace("T", " ")

        if result.valid:
            valid_cell = "[green]✓[/green]"
            passed += 1
        else:
            valid_cell = f"[red]✗ {result.error or 'invalid'}[/red]"
            failed += 1

        table.add_row(str(i), tool_name, valid_cell, timestamp)

    console.print(table)

    total = passed + failed
    if failed == 0:
        console.print(f"\n[green bold]✓ {passed}/{total} signatures valid[/green bold]"
                      " [dim]— audit trail is intact.[/dim]\n")
    else:
        console.print(f"\n[red bold]✗ {failed}/{total} signatures invalid.[/red bold]\n")
        sys.exit(1)
