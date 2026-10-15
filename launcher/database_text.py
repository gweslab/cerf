from __future__ import annotations

from i18n import data_text


def record_key(table: str, row: dict) -> str:
    parts = ["database", table, row["id"]]
    for field in ("board_family_ids", "board_ids"):
        identities = row.get(field)
        if isinstance(identities, list) and identities:
            parts.extend((field, "_".join(sorted(identities))))
    return ".".join(parts)


def field_text(table: str, row: dict, field: str = "name") -> str:
    original = row.get(field, row["id"] if field == "name" else "")
    return data_text(record_key(table, row) + "." + field, original)
