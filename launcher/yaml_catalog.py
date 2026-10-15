from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Set, Tuple

import yaml

LANGUAGE_CODE = re.compile(r"[a-z]{2,3}(?:-(?:[A-Z]{2}|[0-9]{3}))?\Z")
PARAMETER = re.compile(r"[a-z][a-z0-9_]*\Z")
MAX_CATALOG_BYTES = 1024 * 1024


class CatalogLoader(yaml.BaseLoader):
    def resolve(self, kind, value, implicit):
        if kind is yaml.ScalarNode and implicit[0] and value in ("", "~", "null", "Null", "NULL"):
            return "tag:yaml.org,2002:null"
        return super().resolve(kind, value, implicit)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("Invalid or duplicate catalog key: {!r}".format(key))
            result[key] = self.construct_object(value_node, deep=deep)
        return result

    def construct_object(self, node, deep=False):
        if node.tag not in ("tag:yaml.org,2002:str", "tag:yaml.org,2002:map",
                            "tag:yaml.org,2002:seq"):
            raise ValueError("Unsupported YAML tag: " + node.tag)
        return super().construct_object(node, deep=deep)


def message_parts(message: str):
    position = 0
    literal = []
    while position < len(message):
        char = message[position]
        if char not in "{}":
            literal.append(char)
            position += 1
            continue
        if position + 1 < len(message) and message[position + 1] == char:
            literal.append(char)
            position += 2
            continue
        if char == "}":
            raise ValueError("Unmatched closing brace")
        end = message.find("}", position + 1)
        name = message[position + 1:end]
        if end == -1 or not PARAMETER.fullmatch(name):
            raise ValueError("Invalid message placeholder")
        yield "".join(literal), name
        literal = []
        position = end + 1
    yield "".join(literal), None


def message_parameters(message: str) -> Set[str]:
    return {name for _, name in message_parts(message) if name is not None}


def format_message(message: str, **arguments) -> str:
    parts = list(message_parts(message))
    if set(arguments) != {name for _, name in parts if name is not None}:
        raise ValueError("Missing or unexpected message argument")
    return "".join(literal + (str(arguments[name]) if name else "")
                   for literal, name in parts)


def read_catalog(path: Path) -> Tuple[str, Dict[str, str]]:
    with path.open("rb") as stream:
        content = stream.read(MAX_CATALOG_BYTES + 1)
    if len(content) > MAX_CATALOG_BYTES:
        raise ValueError("Catalog exceeds 1 MiB")
    documents = list(yaml.load_all(content.decode("utf-8-sig"), Loader=CatalogLoader))
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise ValueError("Catalog must contain one YAML mapping")
    root = documents[0]
    if (set(root) != {"name", "messages"} or not isinstance(root["name"], str)
            or not root["name"] or "\0" in root["name"]):
        raise ValueError("Catalog requires name and messages")
    messages = root["messages"]
    if not isinstance(messages, dict):
        raise ValueError("Messages must be a mapping")
    for key, value in messages.items():
        if not key or not isinstance(value, str) or "\0" in value or "\0" in key:
            raise ValueError("Catalog values must be text without NUL")
    return root["name"], messages


class TranslationCatalog:
    def __init__(self):
        self.language = "en"
        self.messages: Dict[str, str] = {}
        self.defaults: Dict[str, str] = {}

    def load(self, directory: Path, language: str):
        if not LANGUAGE_CODE.fullmatch(language):
            raise ValueError("Invalid language code")
        _, messages = read_catalog(directory / "en.yml")
        if not messages:
            raise ValueError("English catalog is empty")
        for value in messages.values():
            message_parameters(value)
        defaults = dict(messages)
        warnings = []
        selected = "en"
        if language != "en":
            try:
                _, translations = read_catalog(directory / (language + ".yml"))
                for key, value in translations.items():
                    if key not in messages:
                        warnings.append("Unknown message: " + key)
                        continue
                    try:
                        if message_parameters(value) != message_parameters(messages[key]):
                            raise ValueError("Placeholder mismatch")
                        messages[key] = value
                    except ValueError as error:
                        warnings.append(key + ": " + str(error))
                selected = language
            except (OSError, ValueError, yaml.YAMLError) as error:
                warnings.append(language + ": " + str(error))
        self.messages = messages
        self.defaults = defaults
        self.language = selected
        return warnings

    def data_text(self, key: str, original: str) -> str:
        if self.defaults.get(key) != original:
            return original
        if message_parameters(original):
            return original
        return self.text(key)

    def text(self, key: str, **arguments) -> str:
        return format_message(self.messages[key], **arguments)
