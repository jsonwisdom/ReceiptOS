import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator

def load_json(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)

def main():
    if len(sys.argv) != 3:
        print("Usage: python src/validate.py  ")
        return 2

    schema = load_json(sys.argv[1])
    receipt = load_json(sys.argv[2])

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(receipt), key=lambda e: list(e.path))

    if errors:
        print("INVALID")
        for error in errors:
            location = ".".join(str(p) for p in error.path) or ""
            print(f"{location}: {error.message}")
        return 1

    print("VALID")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())