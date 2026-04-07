"""Tests for pure tool functions."""



from single_agent.tools import read_csv, send_notification, summarize, write_report


def test_read_csv_returns_header_and_rows(tmp_path):
    csv_file = tmp_path / "test.csv"
    csv_file.write_text("month,revenue\nJan,1000\nFeb,2000\n")
    result = read_csv(str(csv_file))
    assert "month" in result
    assert "1000" in result
    assert "2000" in result


def test_read_csv_missing_file():
    result = read_csv("/nonexistent/path/file.csv")
    assert "not found" in result.lower()


def test_read_csv_empty_file(tmp_path):
    csv_file = tmp_path / "empty.csv"
    csv_file.write_text("")
    result = read_csv(str(csv_file))
    assert "empty" in result.lower()


def test_summarize_extracts_numeric_stats():
    data = "month,revenue\nJan,1000\nFeb,2000\nMar,3000"
    result = summarize(data)
    assert "3 records" in result
    assert "6,000" in result  # total
    assert "2,000" in result  # avg


def test_summarize_handles_non_numeric():
    data = "name,city\nAlice,NYC\nBob,LA"
    result = summarize(data)
    assert "2 records" in result


def test_summarize_empty():
    assert "no data" in summarize("").lower()


def test_write_report_creates_file(tmp_path):
    out = tmp_path / "report.md"
    ok = write_report(str(out), "# Report\nContent here.")
    assert ok is True
    assert out.read_text() == "# Report\nContent here."


def test_send_notification_returns_true(capsys):
    ok = send_notification("team", "Hello team!")
    assert ok is True
    captured = capsys.readouterr()
    assert "#team" in captured.out


def test_send_notification_truncates_long_message(capsys):
    long_msg = "x" * 200
    send_notification("alerts", long_msg)
    captured = capsys.readouterr()
    assert "..." in captured.out
