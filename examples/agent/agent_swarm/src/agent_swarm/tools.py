"""Pure tool implementations — no signing or I/O side-effects beyond their stated purpose."""

import csv
from pathlib import Path


def read_csv(path: str) -> str:
    """Read a CSV file and return its contents as a newline-delimited string.

    Args:
        path: Relative or absolute path to the CSV file.

    Usage:
        >>> data = read_csv("data/sales.csv")
    """
    file_path = Path(path)
    if not file_path.exists():
        return f"File not found: {path}"

    with file_path.open(newline="") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        return "Empty file."

    headers = ", ".join(rows[0].keys())
    lines = [headers, *[", ".join(row.values()) for row in rows]]
    return "\n".join(lines)


def summarize(data: str) -> str:
    """Produce a brief statistical summary of CSV-formatted data.

    Args:
        data: Newline-delimited CSV string (header row + data rows).

    Usage:
        >>> summary = summarize(read_csv("data/sales.csv"))
    """
    lines = [ln for ln in data.strip().splitlines() if ln]
    if len(lines) < 2:
        return "No data to summarize."

    headers = lines[0]
    row_count = len(lines) - 1

    try:
        header_list = [h.strip() for h in headers.split(",")]
        last_col = header_list[-1]
        values = [float(row.split(",")[-1].strip()) for row in lines[1:]]
        total = sum(values)
        avg = total / len(values)
        return (
            f"{row_count} records. Columns: {headers}. "
            f"{last_col} — total: {total:,.0f}, avg: {avg:,.0f}."
        )
    except (ValueError, IndexError):
        return f"{row_count} records. Columns: {headers}."


def write_report(path: str, content: str) -> bool:
    """Write a text report to a file.

    Args:
        path: Destination file path.
        content: Report content to write.

    Usage:
        >>> write_report("report.md", "# Sales Summary\\n...")
    """
    Path(path).write_text(content)
    return True


def send_notification(channel: str, message: str) -> bool:
    """Simulate sending a notification to a channel.

    Args:
        channel: Destination channel name (e.g. "team", "alerts").
        message: Notification body.

    Usage:
        >>> send_notification("team", "Monthly report ready.")
    """
    preview = message[:80] + ("..." if len(message) > 80 else "")
    print(f"  [notify → #{channel}] {preview}")
    return True
