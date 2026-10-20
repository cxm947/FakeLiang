"""Resolve the provider named by a frozen binding."""

from src.session.execution_session import SessionReference
from src.session.pipeline_service import PipelineFailure
from .kali import KaliProvider
from .msf import MsfProvider
from .ssh import SshProvider
from .webshell import WebshellProvider


def _control_view(binding):
    """The run's own entry, used only to reach the controller transport.

    A session-bound SSH carrier still sends its ``ssh`` client through the control box.
    The deployment transport validates a controller entry, so the provider must hand it
    one; the session identity stays in the binding used for the actual ssh target.
    """
    value = dict(binding)
    value.update({"binding_kind": "controller_entry", "via": "kali",
                  "host": "kali", "identity": "root", "platform": "linux"})
    return value


def provider_for(binding, *, backend=None, transports=None):
    binding = binding if isinstance(binding, dict) else binding.model_dump()
    if binding.get("binding_kind") == "controller_entry" or binding.get("provider") == "kali":
        if transports is None:
            raise PipelineFailure("会话没接上", "provider_transport_unavailable")
        return KaliProvider(binding, transports)
    provider = str(binding.get("provider") or "msf").strip().lower()
    if provider == "msf":
        if backend is None:
            raise PipelineFailure("会话没接上", "provider_backend_unavailable")
        return MsfProvider(backend, SessionReference.model_validate(binding["session"]))
    if provider == "ssh":
        if transports is None:
            raise PipelineFailure("会话没接上", "provider_transport_unavailable")
        key_path = str(binding.get("ssh_key_path") or "").strip()
        if not key_path:
            # The key is deployment-owned; a default path would silently point at a
            # different run's material on a shared controller.
            raise PipelineFailure("参数没给到", "provider_ssh_key_missing")
        return SshProvider(binding, KaliProvider(_control_view(binding), transports),
                           key_path=key_path, port=int(binding.get("ssh_port") or 22))
    if provider == "webshell":
        url = str(binding.get("webshell_url") or "").strip()
        if not url:
            raise PipelineFailure("会话没接上", "provider_webshell_url_missing")
        return WebshellProvider(url, parameter=str(binding.get("webshell_parameter") or "cmd"))
    raise PipelineFailure("参数没给到", "provider_unknown: " + provider)
