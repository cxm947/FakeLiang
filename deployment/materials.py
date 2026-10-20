"""Push deployment-owned files to the execution point, on demand, per run.

Scripts live with the deployment, never pre-staged on the target. A run pushes
only what its configuration declares, verifies the content on both ends, and
hands the resolved execution-point paths to the Action input as ``materials``.
"""

from base64 import b64encode
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.agents.pre_verifier.schema import ExecutionRequest
from src.agents.pre_verifier.mcp_client import command_for
from src.session.pipeline_service import PipelineFailure


#: One command line stays well below the execution bridge's argument limit.
CHUNK = 12000


class MaterialSpec(BaseModel):
    """One declared deployment file and the path it must occupy when used."""

    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1)
    #: Local paths are deployment configuration, therefore always text.
    source: str = Field(min_length=1)
    remote_path: str = Field(min_length=1)
    #: A pushed archive may be unpacked at the execution point; the material then
    #: resolves to ``resolved_path`` instead of the archive itself.
    extract_to: str | None = None
    resolved_path: str | None = None
    sha256: str | None = None
    mode: str = "0644"

    @model_validator(mode="after")
    def execution_paths_are_posix(self):
        for field in ("extract_to", "resolved_path"):
            value = getattr(self, field)
            if value is not None and not value.startswith("/"):
                raise ValueError(field + " must be an absolute POSIX path")
        return self

    def digest(self) -> str:
        try:
            content = Path(self.source).read_bytes()
        except OSError:
            raise PipelineFailure("参数没给到", "materials_source_missing") from None
        digest = sha256(content).hexdigest()
        if self.sha256 is not None:
            declared = str(self.sha256).strip().lower()
            if len(declared) != 64 or declared != digest:
                raise PipelineFailure("参数没给到", "materials_digest_mismatch")
        return digest


def _push_command(spec, content, digest):
    import posixpath
    import shlex

    payload = b64encode(content).decode("ascii")
    # The execution point is a POSIX host: `Path(...).parent` on the controller would turn
    # `/tmp/tools/x` into `\tmp\tools`, and `mkdir -p` then creates a literal backslash
    # directory while the declared path stays missing (live 2026-10-18, node 28 materials).
    parent = posixpath.dirname(spec.remote_path) or "/"
    temporary = spec.remote_path + ".part"
    remote = shlex.quote(spec.remote_path)
    command = ("mkdir -p " + shlex.quote(parent) + " && printf '%s' '" + payload
               + "' | base64 -d > " + shlex.quote(temporary) + " && chmod " + spec.mode
               + " " + shlex.quote(temporary) + " && mv -f " + shlex.quote(temporary)
               + " " + remote)
    target = spec.resolved_path or spec.remote_path
    if spec.extract_to:
        command += (" && mkdir -p " + shlex.quote(spec.extract_to)
                    + " && tar -xzf " + remote + " -C " + shlex.quote(spec.extract_to))
    if spec.resolved_path:
        command += (" && chmod " + spec.mode + " " + shlex.quote(target)
                    + " && test -x " + shlex.quote(target))
    command += " && sha256sum " + remote
    return command


def _commands(spec, content, digest):
    """One command for a small file; a staged append/decode sequence for a large one."""
    payload = b64encode(content).decode("ascii")
    if len(payload) <= CHUNK:
        return [_push_command(spec, content, digest)]
    import posixpath
    import shlex

    parent = posixpath.dirname(spec.remote_path) or "/"
    remote = shlex.quote(spec.remote_path)
    staged = shlex.quote(spec.remote_path + ".b64")
    temporary = shlex.quote(spec.remote_path + ".part")
    commands = ["mkdir -p " + shlex.quote(parent) + " && rm -f " + staged
                + " && : > " + staged]
    for offset in range(0, len(payload), CHUNK):
        commands.append("printf %s " + shlex.quote(payload[offset:offset + CHUNK])
                        + " >> " + staged)
    final = ("base64 -d " + staged + " > " + temporary
             + " && chmod " + spec.mode + " " + temporary
             + " && mv -f " + temporary + " " + remote)
    target = spec.resolved_path or spec.remote_path
    if spec.extract_to:
        final += (" && mkdir -p " + shlex.quote(spec.extract_to)
                  + " && tar -xzf " + remote + " -C " + shlex.quote(spec.extract_to))
    if spec.resolved_path:
        final += (" && chmod " + spec.mode + " " + shlex.quote(target)
                  + " && test -x " + shlex.quote(target))
    final += " && rm -f " + staged + " && sha256sum " + remote
    commands.append(final)
    return commands


def push(transports, binding, specs, *, directory=None, probe=None):
    """Push every declared file and return {name: execution-point path}.

    The receipt records only digests and paths; a failed digest leaves no
    half-written file at the declared path because the write is staged first.
    """
    from deployment.session_owner import ExecutionSessionOwner

    observed = (probe or transports.execute)
    resolved, records = {}, []
    for spec in (MaterialSpec.model_validate(item) for item in (specs or [])):
        digest = spec.digest()
        content = Path(spec.source).read_bytes()
        result = {"effect_known": False, "response": {}}
        for command in _commands(spec, content, digest):
            request = ExecutionRequest(tool="cmd", name="bash", via=binding["via"],
                                       content=command)
            try:
                result = observed(deepcopy(binding), request.model_dump())
            except PipelineFailure:
                result = {"effect_known": False, "response": {}}
            except Exception:
                result = {"effect_known": False, "response": {}}
            if not result.get("effect_known"):
                break
        text = (ExecutionSessionOwner._stdout_text(result.get("response"))
                if isinstance(result, dict) else "")
        remote = next((line.split()[0].strip() for line in text.splitlines()
                       if line.strip().startswith(digest)), None)
        record = {"name": spec.name, "remote_path": spec.remote_path, "sha256": digest,
                  "pushed": bool(result.get("effect_known")) and remote == digest}
        if not record["pushed"]:
            record["category"], record["detail"] = "会话没接上", "materials_push_unconfirmed"
        records.append(record)
        if record["pushed"]:
            resolved[spec.name] = spec.resolved_path or spec.remote_path
    if directory is not None:
        from run_action import save
        save(Path(directory) / "materials.json", records)
    failed = next((row for row in records if not row["pushed"]), None)
    if failed is not None:
        raise PipelineFailure(failed["category"], failed["detail"])
    return resolved
