"""Read-only POSIX path observation; no final LEAF verdict and no transport."""

import argparse
import json
import os


def inspect_path(path):
    result = {"path": path, "identity": None, "uid": None,
              "exists": None, "writable": None, "error": None}
    if os.name != "posix":
        result["error"] = "POSIX effective-identity checks are not available"
        return result
    import pwd
    result["uid"] = os.geteuid()
    try:
        result["identity"] = pwd.getpwuid(result["uid"]).pw_name
    except KeyError:
        result["identity"] = str(result["uid"])
    try:
        os.stat(path)
        result["exists"] = True
        if os.access not in os.supports_effective_ids:
            result["error"] = "Effective-identity access checks are not supported"
        else:
            result["writable"] = os.access(path, os.W_OK, effective_ids=True)
    except (FileNotFoundError, NotADirectoryError):
        result["exists"] = False
        result["writable"] = False
    except OSError as exc:
        result["error"] = type(exc).__name__
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True)
    args = parser.parse_args()
    print(json.dumps(inspect_path(args.path), ensure_ascii=False))


if __name__ == "__main__":
    main()
