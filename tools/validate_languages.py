import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "launcher"))

from yaml_catalog import LANGUAGE_CODE, message_parameters, read_catalog
from database_text import record_key


def validate():
    errors = []
    _, english = read_catalog(ROOT / "langs" / "en.yml")
    for key, value in english.items():
        try:
            message_parameters(value)
        except ValueError as error:
            errors.append("en: {}: {}".format(key, error))
    for path in sorted((ROOT / "langs").glob("*.yml")):
        if not LANGUAGE_CODE.fullmatch(path.stem):
            errors.append("Invalid language filename: " + path.name)
            continue
        _, messages = read_catalog(path)
        for key, value in messages.items():
            if key not in english:
                errors.append("{}: unknown key {}".format(path.stem, key))
                continue
            try:
                if message_parameters(value) != message_parameters(english[key]):
                    errors.append("{}: placeholder mismatch {}".format(path.stem, key))
            except ValueError as error:
                errors.append("{}: {}: {}".format(path.stem, key, error))
        print("{}: {}/{} messages; {} English fallbacks".format(
            path.stem, len(messages), len(english), len(english.keys() - messages.keys())))
    referenced = set()
    database = json.loads((ROOT / "bundled" / "db.json").read_text(encoding="utf-8"))
    for table, rows in database.items():
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                continue
            prefix = record_key(table, row)
            fields = [(prefix + "." + field, row[field])
                      for field in ("name", "note") if isinstance(row.get(field), str)]
            fields += [(prefix + ".notes." + str(index), note)
                       for index, note in enumerate(row.get("notes", []))]
            fields += [(prefix + ".enum_values." + option["id"], option["name"])
                       for option in row.get("enum_values", [])]
            for key, original in fields:
                if key in english and english[key] != original:
                    errors.append("English metadata differs from database: " + key)
    for path in (ROOT / "launcher").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "t":
                if node.args and isinstance(node.args[0], ast.Str):
                    key = node.args[0].s
                    referenced.add(key)
                    if key in english and all(argument.arg for argument in node.keywords):
                        actual = {argument.arg for argument in node.keywords}
                        try:
                            required = message_parameters(english[key])
                            if actual != required:
                                errors.append("{}:{}: argument mismatch for {}".format(
                                    path.relative_to(ROOT), node.lineno, key))
                        except ValueError:
                            pass
    for path in list((ROOT / "cerf").rglob("*.cpp")) + list((ROOT / "cerf").rglob("*.h")):
        source = path.read_text(encoding="utf-8-sig")
        for call in re.finditer(r'(?:\.|->)(Text|Format)\(\s*"([a-z_][a-z0-9_.]+)"', source):
            method, key = call.groups()
            referenced.add(key)
            if method == "Text" and key in english:
                try:
                    if message_parameters(english[key]):
                        errors.append("{}: Text requires an argument-free message: {}".format(
                            path.relative_to(ROOT), key))
                except ValueError:
                    pass
        referenced.update(re.findall(r'SourceLabelKey\(\).*?return\s+"([a-z_][a-z0-9_.]+)"', source))
        referenced.update(re.findall(r'display_key\s*=\s*"([a-z_][a-z0-9_.]+)"', source))
    for key in sorted(referenced - english.keys()):
        errors.append("Message referenced in code but absent from en.yml: " + key)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Catalog validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(validate())
