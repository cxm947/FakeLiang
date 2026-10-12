"""Remote executor checks: argv quoting, outcome mapping, transport failures. Offline (fake client)."""

import socket
import tempfile
import unittest
from pathlib import Path

from tests.support import ROOT

from runtime.remote import RemoteTarget, SshExecutor, command_line, parse_remote
from runtime.runner import ExecOutcome, execute


class FakeChannel:
    def __init__(self, code):
        self.code = code

    def recv_exit_status(self):
        return self.code


class FakeStream:
    def __init__(self, data=b"", channel=None):
        self.data = data
        self.channel = channel

    def read(self):
        return self.data


class FakeClient:
    def __init__(self, code=0, out=b"", err=b"", raises=None):
        self.code, self.out, self.err, self.raises = code, out, err, raises
        self.commands = []
        self.closed = False

    def exec_command(self, command, timeout=None):
        self.commands.append((command, timeout))
        if self.raises is not None:
            raise self.raises
        return None, FakeStream(self.out, FakeChannel(self.code)), FakeStream(self.err)

    def close(self):
        self.closed = True


def client_factory(client):
    calls = []

    def make(target, password, key_filename):
        calls.append((target, password, key_filename))
        return client

    make.calls = calls
    return make


class ParseRemoteTests(unittest.TestCase):
    def test_accepted_shapes(self):
        self.assertEqual(RemoteTarget("10.0.0.5"), parse_remote("10.0.0.5"))
        target = parse_remote("kali@192.168.52.128:2222")
        self.assertEqual(("kali", "192.168.52.128", 2222), (target.username, target.host, target.port))
        self.assertEqual("kali@192.168.52.128", parse_remote("kali@192.168.52.128").label())

    def test_bad_values_stop_with_a_message(self):
        for value in ("", "kali@", "host:notaport", "host:70000"):
            with self.assertRaises(SystemExit):
                parse_remote(value)


class CommandLineTests(unittest.TestCase):
    def test_argv_is_quoted_for_posix(self):
        self.assertEqual("echo 'a b' 'c;d'", command_line(["echo", "a b", "c;d"]))


class SshExecutorTests(unittest.TestCase):
    def test_argv_reaches_the_remote_shell_and_the_exit_code_is_kept(self):
        client = FakeClient(code=0, out=b"PC1\n")
        factory = client_factory(client)
        executor = SshExecutor(RemoteTarget("host", "kali"), password="pw", client_factory=factory)
        outcome = executor(("whoami",), 30.0)
        self.assertEqual(ExecOutcome(0, "PC1\n", ""), outcome)
        self.assertEqual([("whoami", 30.0)], client.commands)
        self.assertEqual(1, len(factory.calls))
        executor.close()
        self.assertTrue(client.closed)

    def test_exit_127_is_a_missing_tool_not_a_target_fact(self):
        client = FakeClient(code=127, err=b"bash: nmap: command not found\n")
        executor = SshExecutor(RemoteTarget("host", "kali"), client_factory=client_factory(client))
        outcome = executor(("nmap", "-p", "80"), 30.0)
        self.assertIn("command not found on kali@host", outcome.tool_error)
        self.assertEqual("tool_missing", _status_of(outcome))

    def test_exit_127_with_output_keeps_the_calls_own_rc(self):
        """run114: a runtime-wrapped call prints its marker lines first; a 127 that still has
        output is the query's own reading, not a missing entry point."""
        client = FakeClient(code=127, out=b"agvdeadbeefstart\nagvdeadbeefend\n")
        executor = SshExecutor(RemoteTarget("host", "kali"), client_factory=client_factory(client))
        outcome = executor(("/bin/sh", "-c", "sh -c 'command -v x'"), 30.0)
        self.assertIsNone(outcome.tool_error)
        self.assertEqual(127, outcome.returncode)
        self.assertEqual("executed", _status_of(outcome))

    def test_timeout_closes_the_session_and_the_next_call_reconnects(self):
        client = FakeClient(raises=socket.timeout())
        factory = client_factory(client)
        executor = SshExecutor(RemoteTarget("host"), client_factory=factory)
        first = executor(("sleep", "999"), 1.0)
        self.assertTrue(first.timed_out)
        self.assertTrue(client.closed)
        second = executor(("sleep", "999"), 1.0)
        self.assertTrue(second.timed_out)
        self.assertEqual(2, len(factory.calls))

    def test_transport_failure_never_becomes_evidence(self):
        client = FakeClient(raises=OSError("connection reset"))
        executor = SshExecutor(RemoteTarget("host"), client_factory=client_factory(client))
        outcome = executor(("nmap",), 10.0)
        self.assertIsNone(outcome.returncode)
        self.assertIn("executor failed", outcome.stderr)
        with tempfile.TemporaryDirectory() as directory:
            call = execute(["nmap"], run_dir=directory, skill_id="demo.skill", executor=executor)
        self.assertEqual("transport_error", call.status)
        self.assertIsNone(call.returncode)


def _status_of(outcome):
    from runtime.runner import CallResult
    dummy = CallResult("id", "demo", [], outcome.returncode, outcome.stdout, outcome.stderr,
                       outcome.timed_out, outcome.tool_error, "now", 0.0, None)
    return dummy.status




if __name__ == "__main__":
    unittest.main()
