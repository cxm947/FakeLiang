"""Shared test helpers: the repo root and the entry-point roster.

Everything else a test needs it imports straight from the module under test. These helpers stay
here because the layout guard derives the roster from the directory instead of keeping a second
copy of the list.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Scripts under ``scripts/`` that are libraries rather than command line entries (they have no
#: ``--help`` of their own). Everything else must answer ``--help`` from any directory.
LIBRARY_SCRIPTS: tuple = ("reclaim_hosts.py",)


def entry_point_names():
    """Every command line entry under ``scripts/``, sorted; derived from the folder."""
    return sorted(path.name for path in (ROOT / "scripts").glob("*.py")
                  if path.name not in LIBRARY_SCRIPTS)


def stub_callers(monkeypatch, name, value, *, callers):
    """Stub a collaborator in the modules the test names, and nowhere else.

    A function that moved into the orchestration package reads its collaborators from its own
    module globals, so a seam is patched where the caller looks the name up. The caller modules
    are declared per call instead of being discovered, so a typo cannot quietly patch nothing -
    every target is checked before the first replacement is made.
    """
    callers = tuple(callers)
    if not callers:
        raise AssertionError("stub_callers needs the modules that look %s up" % name)
    for caller in callers:
        if name not in vars(caller):
            raise AssertionError("missing patch target: %s.%s"
                                 % (getattr(caller, "__name__", caller), name))
    for caller in callers:
        monkeypatch.setattr(caller, name, value)
    return [getattr(caller, "__name__", str(caller)) for caller in callers]


class FakeClock:
    """Advance a synchronous deadline without sleeping in offline tests."""
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def time(self):
        return 1700000000.0 + self.now

    def sleep(self, seconds):
        self.now += seconds


def session_binding(*, sid="1", session_type="shell", platform="linux", capacity=65536):
    return {"kind": "console_session", "channel_id": "test-" + sid,
            "session_id": sid, "session_type": session_type, "platform": platform,
            "endpoint": {"host": "127.0.0.1", "port": 55553, "ssl": False},
            "shell_ready": True,
            "capacity": {"max_bytes": capacity, "source": "test declaration"}}


def bound_action(text="already bound\n", *, marker="agvtest", operation="shell"):
    return {"operation": operation, "text": text,
            "completion": {"marker": marker} if marker is not None else None}


class FakeConsole:
    """Return explicitly scripted remote bytes; never manufacture completion frames."""
    def __init__(self, *, prompt="root@lab:~#", answer=True, when_written=(), when_run=()):
        self.prompt, self.answer = prompt, bool(answer)
        self.when_written, self.when_run = list(when_written), list(when_run)
        self.queue, self.writes, self.singles, self.deadlines = [], [], [], []

    def _rules(self, text, rules):
        for needle, reply in rules:
            if needle in text:
                self.queue.append(reply)
                return True
        return False

    def write(self, text):
        self.writes.append(text)
        if self.answer:
            self._rules(text, self.when_written)

    def run(self, verb):
        self.singles.append(verb)
        if self.answer:
            self._rules(verb, self.when_run)

    def pop(self):
        return self.queue.pop(0) if self.queue else ""


def wire_console(monkeypatch, console=None, *, session_type="shell", tmp_path=None, **kwargs):
    """Bind synchronous fake RPCs to one deadline and an isolated real lock directory."""
    import tempfile
    from runtime import channels, msfservice

    console = console or FakeConsole(**kwargs)
    console.clock = FakeClock()
    if tmp_path is None:
        console._temporary = tempfile.TemporaryDirectory(prefix="agv-console-test-")
        tmp_path = console._temporary.name
    monkeypatch.setattr(channels.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(channels, "time", console.clock)
    monkeypatch.setenv("AGV_MSF_RPC", "msf:pw@127.0.0.1:55553")

    def client_for(endpoint, *, deadline):
        console.deadlines.append(deadline)
        return console

    def shape(client, sid, *, deadline):
        console.deadlines.append(deadline)
        return {"sid": sid, "type": session_type}

    def write(client, sid, text, *, deadline):
        console.deadlines.append(deadline)
        console.write(text)

    def read(client, sid, *, deadline):
        console.deadlines.append(deadline)
        return console.pop()

    def native(client, sid, text, *, deadline):
        console.deadlines.append(deadline)
        console.run(text)
        return ""

    monkeypatch.setattr(msfservice, "client_for", client_for)
    monkeypatch.setattr(msfservice, "session_shape", shape)
    monkeypatch.setattr(msfservice, "write", write)
    monkeypatch.setattr(msfservice, "read", read)
    monkeypatch.setattr(msfservice, "runsingle", native)
    monkeypatch.setattr(msfservice, "shell_write", write)
    monkeypatch.setattr(msfservice, "shell_read", read)
    return console
