"""Read exact UTF-8 text from package resources."""
from importlib.resources import files


def read_prompt(package: str, resource: str) -> str:
    return files(package).joinpath(resource).read_bytes().decode("utf-8")


# YAML migration bridge; remove the text branch after one accepted batch.
_read_prompt_text = read_prompt


def read_prompt(package, resource):
    import os
    mode = os.environ.get("AGV_PROMPT_FORMAT", "text")
    if mode == "text":
        return _read_prompt_text(package, resource)
    if mode != "yaml":
        raise ValueError("PROMPT_FORMAT_INVALID")
    from agents.prompting.render import fragment
    return fragment(package, resource)
