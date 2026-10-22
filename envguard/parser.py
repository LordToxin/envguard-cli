"""Robust .env file parser with multiline, export syntax, and line numbering support."""

from dataclasses import dataclass
from typing import Dict, List, Optional
import os
import re

@dataclass
class EnvEntry:
    key: str
    value: str
    line_number: int
    raw_line: str
    filepath: str
    comment: Optional[str] = None
    is_exported: bool = False

def parse_dotenv(content: str, filepath: str = ".env") -> List[EnvEntry]:
    """Parse .env content and return a list of EnvEntry objects with line metadata."""
    entries: List[EnvEntry] = []
    lines = content.splitlines()
    i = 0
    total_lines = len(lines)

    while i < total_lines:
        line_num = i + 1
        raw_line = lines[i]
        line = raw_line.strip()

        # Skip empty lines or pure comment lines
        if not line or line.startswith("#"):
            i += 1
            continue

        is_exported = False
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[6:].lstrip()
            is_exported = True

        if "=" not in line:
            i += 1
            continue

        key, rest = line.split("=", 1)
        key = key.strip()

        if not key:
            i += 1
            continue

        rest = rest.lstrip()
        value = ""
        inline_comment = None

        # Check for quoted multiline or single line values
        if rest.startswith(('"', "'")):
            quote_char = rest[0]
            # Check if quote ends on the same line
            escaped = False
            closing_idx = -1
            for idx in range(1, len(rest)):
                char = rest[idx]
                if char == "\\" and not escaped:
                    escaped = True
                    continue
                if char == quote_char and not escaped:
                    closing_idx = idx
                    break
                escaped = False

            if closing_idx != -1:
                # Closed on same line
                val_content = rest[1:closing_idx]
                trailing = rest[closing_idx + 1:].strip()
                if trailing.startswith("#"):
                    inline_comment = trailing[1:].strip()
                value = val_content
            else:
                # Multiline quoted string
                val_parts = [rest[1:]]
                i += 1
                found_close = False
                while i < total_lines:
                    curr_line = lines[i]
                    # Search for closing quote
                    escaped = False
                    c_idx = -1
                    for idx, char in enumerate(curr_line):
                        if char == "\\" and not escaped:
                            escaped = True
                            continue
                        if char == quote_char and not escaped:
                            c_idx = idx
                            break
                        escaped = False
                    if c_idx != -1:
                        val_parts.append(curr_line[:c_idx])
                        trailing = curr_line[c_idx + 1:].strip()
                        if trailing.startswith("#"):
                            inline_comment = trailing[1:].strip()
                        found_close = True
                        break
                    else:
                        val_parts.append(curr_line)
                    i += 1
                value = "\n".join(val_parts)
        else:
            # Unquoted value: split inline comments
            if " #" in rest or "\t#" in rest:
                match = re.search(r"[\s]+#", rest)
                if match:
                    value = rest[:match.start()].strip()
                    inline_comment = rest[match.end():].strip()
                else:
                    value = rest.strip()
            else:
                value = rest.strip()

        entries.append(
            EnvEntry(
                key=key,
                value=value,
                line_number=line_num,
                raw_line=raw_line,
                filepath=filepath,
                comment=inline_comment,
                is_exported=is_exported,
            )
        )
        i += 1

    return entries

def load_env_file(filepath: str) -> List[EnvEntry]:
    """Read a file from disk and parse its dotenv contents."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    return parse_dotenv(content, filepath=filepath)
