"""Every text line of ``artzain audit verify`` fits in 90 columns and is ASCII.

The lines are the ones the command prints, rendered with the widest realistic
values: a 6-digit seq, a 26-character seal id, a 16-character key id, and a
count of 12,105. The indent is part of the line (``  ! `` before a warning,
``    - `` before a ``--verbose`` detail).
"""

from __future__ import annotations

from artzain.cli import audit_verify_sample_lines


def test_every_audit_verify_line_fits_in_90_columns_and_is_ascii():
    lines = audit_verify_sample_lines()
    assert len(lines) > 40
    for line in lines:
        assert len(line) <= 90, (len(line), line)
        assert line.isascii(), line
