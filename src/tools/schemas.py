"""Typed arguments for every tool the model may call."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RunCommandArgs(_Args):
    interpreter: Literal["sh", "bash", "cmd", "powershell", "python3"]
    command: str = Field(min_length=1)
    timeout: int = Field(default=30, ge=1, le=120)


class RunScriptArgs(_Args):
    interpreter: Literal["python3", "bash", "sh", "powershell"]
    body: str = Field(min_length=1)
    timeout: int = Field(default=60, ge=1, le=300)


class HttpRequestArgs(_Args):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    url: str = Field(min_length=1)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    multipart: dict[str, str] = Field(default_factory=dict)


class StageFileArgs(_Args):
    path: str = Field(pattern=r"^/", min_length=2)
    text: str = Field(min_length=1)


class SessionCommandArgs(_Args):
    command: str = Field(min_length=1, max_length=2000)


class MsfJobArgs(_Args):
    action: Literal["job_list", "job_stop"]
    job_id: str = Field(default="", pattern=r"^[0-9]*$")


class CredentialTestArgs(_Args):
    """Validate one stored credential against one host with an MSF login scanner."""

    method: Literal["smb", "ldap", "winrm", "kerberos"] = "smb"
    host: str = Field(min_length=1, max_length=255)
    credential_ref: str = Field(min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    timeout: int = Field(default=60, ge=1, le=300)


class ServeFileArgs(_Args):
    directory: str = Field(pattern=r"^/", min_length=2)
    port: int = Field(ge=1, le=65535)


class RemoteProcessArgs(_Args):
    host: str = Field(min_length=1)
    #: Native-upload psexec runs the runtime's own payload as the service binary, so a node
    #: that only needs a channel has no command line to compose.
    command: str = ""
    credential_ref: str = ""
    method: Literal["wmic", "psexec", "msf_psexec", "wmiexec", "smb_copy", "schtasks",
                    "sc", "smbexec"] = "wmic"
    local_path: str = ""
    remote_path: str = ""
