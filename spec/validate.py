#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate channel-entry documents against channel-entry.schema.json.

Usage: python3 spec/validate.py FILE [FILE...]
Exit 0 only when every file validates. Requires the jsonschema package.
"""
import json
import pathlib
import sys

SCHEMA_PATH = pathlib.Path(__file__).resolve().parent / "channel-entry.schema.json"


def load_schema():
    return json.loads(SCHEMA_PATH.read_text())


def validate_file(path, schema):
    import jsonschema

    doc = json.loads(pathlib.Path(path).read_text())
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    return errors


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        print("validate.py: the jsonschema package is required (pip install jsonschema)")
        return 2
    schema = load_schema()
    failed = False
    for path in argv:
        errors = validate_file(path, schema)
        if errors:
            failed = True
            print(f"INVALID {path}")
            for e in errors:
                loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
                print(f"  at {loc}: {e.message}")
        else:
            print(f"valid   {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
