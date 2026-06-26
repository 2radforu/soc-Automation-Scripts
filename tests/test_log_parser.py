import json
from pathlib import Path

from log_parser import parse_logs


def test_parse_substring(tmp_path: Path):
    input_file = tmp_path / "in.log"
    output_file = tmp_path / "out.json"

    input_file.write_text(
        "2026-06-25 14:04:10 webapp[54321]: Malicious request detected from 198.51.100.23 - /admin.php\n"
    )

    count = parse_logs(str(input_file), str(output_file), pattern="Malicious", use_regex=False, out_format="json")
    assert count == 1

    data = output_file.read_text().splitlines()
    assert len(data) == 1
    obj = json.loads(data[0])
    assert "Malicious request" in obj["event"]
    assert obj["rule"] == "pattern: Malicious"


def test_parse_regex(tmp_path: Path):
    input_file = tmp_path / "in2.log"
    output_file = tmp_path / "out2.json"

    input_file.write_text(
        "2026-06-25 14:06:01 api[3333]: MALICIOUS_PAYLOAD detected in request body from 192.0.2.11\n"
    )

    # use a case-insensitive regex to catch MALICIOUS_PAYLOAD
    count = parse_logs(str(input_file), str(output_file), pattern="MALICIOUS_PAYLOAD", use_regex=True, out_format="json")
    assert count == 1
    obj = json.loads(output_file.read_text().splitlines()[0])
    assert "MALICIOUS_PAYLOAD" in obj["event"]
