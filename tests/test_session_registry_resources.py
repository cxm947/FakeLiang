import json
import multiprocessing
from pathlib import Path
from unittest.mock import create_autospec

import pytest

from runtime import session_registry


def test_held_resources_reads_resource_registry(tmp_path):
    resource = {
        "host": "192.0.2.10",
        "port": 1080,
        "protocol": "tcp",
    }
    session_registry.reserve_resources(
        tmp_path, owner="owner-a", resources=[resource])

    ledger = tmp_path / "session-resources" / "sessions.json"
    assert ledger.is_file()
    assert not (tmp_path / "sessions.json").exists()
    assert session_registry.held_resources(tmp_path) == [
        ["192.0.2.10", 1080],
    ]


def test_held_resources_does_not_read_main_registry(tmp_path):
    main_resource = {
        "host": "192.0.2.10",
        "port": 1080,
        "protocol": "tcp",
    }
    main_key = json.dumps(
        main_resource, sort_keys=True, separators=(",", ":"))

    def write_main_registry(value):
        value["resources"][main_key] = {
            "owner": "main-owner",
            "state": "held",
            "at": 1.0,
        }

    session_registry._mutate(tmp_path, write_main_registry)

    assert (tmp_path / "sessions.json").is_file()
    assert session_registry.held_resources(tmp_path) == []

    session_registry.reserve_resources(
        tmp_path,
        owner="resource-owner",
        resources=[{
            "host": "192.0.2.20",
            "port": 2090,
            "protocol": "tcp",
        }],
    )

    assert session_registry.held_resources(tmp_path) == [
        ["192.0.2.20", 2090],
    ]
    assert main_key in session_registry._registry(tmp_path)["resources"]


@pytest.mark.parametrize("host,expected", [
    ("", [["192.0.2.10", 1080], ["192.0.2.20", 2090]]),
    ("192.0.2.10", [["192.0.2.10", 1080]]),
    ("192.0.2.20", [["192.0.2.20", 2090]]),
    ("192.0.2.30", []),
])
def test_held_resources_filters_host(tmp_path, host, expected):
    session_registry.reserve_resources(
        tmp_path,
        owner="owner-a",
        resources=[
            {"host": "192.0.2.10", "port": 1080, "protocol": "tcp"},
            {"host": "192.0.2.20", "port": 2090, "protocol": "tcp"},
        ],
    )

    actual = session_registry.held_resources(tmp_path, host=host)
    assert sorted(actual) == sorted(expected)


@pytest.mark.parametrize("directory_exists", [False, True])
def test_held_resources_missing_registry_is_empty(
        tmp_path, directory_exists):
    root = tmp_path / "run"
    resource_directory = root / "session-resources"
    if directory_exists:
        resource_directory.mkdir(parents=True)

    assert session_registry.held_resources(root) == []
    assert not (resource_directory / "sessions.json").exists()
    assert resource_directory.exists() == directory_exists
    assert root.exists() == directory_exists


def test_held_resources_keeps_all_active_owners(tmp_path):
    session_registry.reserve_resources(
        tmp_path,
        owner="old-owner",
        resources=[{
            "host": "192.0.2.10",
            "port": 1080,
            "protocol": "tcp",
        }],
    )
    session_registry.reserve_resources(
        tmp_path,
        owner="other-owner",
        resources=[{
            "host": "192.0.2.10",
            "port": 2090,
            "protocol": "udp",
        }],
    )

    def age_reservations(value):
        for lease in value["resources"].values():
            lease["at"] = 0.0

    session_registry._mutate(
        session_registry._resource_root(tmp_path),
        age_reservations,
    )

    assert sorted(session_registry.held_resources(tmp_path)) == [
        ["192.0.2.10", 1080],
        ["192.0.2.10", 2090],
    ]


def test_held_resources_reflects_confirmed_release(tmp_path):
    resource_a = {
        "host": "192.0.2.10",
        "port": 1080,
        "protocol": "tcp",
    }
    resource_b = {
        "host": "192.0.2.10",
        "port": 1081,
        "protocol": "tcp",
    }
    session_registry.reserve_resources(
        tmp_path, owner="owner-a", resources=[resource_a])
    session_registry.reserve_resources(
        tmp_path, owner="owner-b", resources=[resource_b])

    receipts = [{"confirmed": True, "command_rc": 0}]
    session_registry.release_resources(
        tmp_path, owner="owner-a", receipts=receipts)

    assert session_registry.held_resources(tmp_path) == [
        ["192.0.2.10", 1081],
    ]

    value = session_registry._registry(
        session_registry._resource_root(tmp_path))
    key_a = json.dumps(
        resource_a, sort_keys=True, separators=(",", ":"))

    assert key_a not in value["resources"]
    assert value["releases"]["owner-a"]["receipts"] == receipts
    assert value["releases"]["owner-a"]["resources"] == [key_a]
    assert "owner-b" not in value["releases"]
    assert {
        lease["owner"] for lease in value["resources"].values()
    } == {"owner-b"}


@pytest.mark.parametrize("corruption", [
    "invalid_json_key",
    "non_object_key",
    "noncanonical_key",
    "missing_resource_field",
    "empty_host",
    "boolean_port",
    "zero_port",
    "port_out_of_range",
    "invalid_protocol",
    "non_object_lease",
    "empty_owner",
    "non_string_owner",
    "released_state",
    "unknown_state",
    "released_owner_still_held",
])
def test_held_resources_rejects_corrupt_records(tmp_path, corruption):
    session_registry.reserve_resources(
        tmp_path,
        owner="owner-a",
        resources=[{
            "host": "192.0.2.10",
            "port": 1080,
            "protocol": "tcp",
        }],
    )
    ledger = tmp_path / "session-resources" / "sessions.json"
    value = json.loads(ledger.read_text(encoding="utf-8"))
    original_key, lease = next(iter(value["resources"].items()))
    resource = json.loads(original_key)
    key_override = None

    if corruption == "invalid_json_key":
        key_override = "{"
    elif corruption == "non_object_key":
        key_override = "[]"
    elif corruption == "noncanonical_key":
        key_override = json.dumps(resource, sort_keys=True)
    elif corruption == "missing_resource_field":
        del resource["protocol"]
    elif corruption == "empty_host":
        resource["host"] = ""
    elif corruption == "boolean_port":
        resource["port"] = True
    elif corruption == "zero_port":
        resource["port"] = 0
    elif corruption == "port_out_of_range":
        resource["port"] = 65536
    elif corruption == "invalid_protocol":
        resource["protocol"] = "icmp"
    elif corruption == "non_object_lease":
        lease = []
    elif corruption == "empty_owner":
        lease["owner"] = ""
    elif corruption == "non_string_owner":
        lease["owner"] = 7
    elif corruption == "released_state":
        lease["state"] = "released"
    elif corruption == "unknown_state":
        lease["state"] = "unknown"

    key = (
        key_override
        if key_override is not None
        else json.dumps(resource, sort_keys=True, separators=(",", ":"))
    )
    value["resources"] = {key: lease}

    if corruption == "released_owner_still_held":
        value["releases"]["owner-a"] = {
            "receipts": [{"confirmed": True, "command_rc": 0}],
            "at": 1.0,
            "resources": [key],
        }

    ledger.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(
            ValueError, match="^SESSION_RESOURCE_REGISTRY_INVALID$"):
        session_registry.held_resources(tmp_path)


@pytest.mark.parametrize("failure,exception_type", [
    ("invalid_json", json.JSONDecodeError),
    ("permission", PermissionError),
])
def test_held_resources_does_not_hide_read_errors(
        tmp_path, monkeypatch, failure, exception_type):
    session_registry.reserve_resources(
        tmp_path,
        owner="owner-a",
        resources=[{
            "host": "192.0.2.10",
            "port": 1080,
            "protocol": "tcp",
        }],
    )
    ledger = tmp_path / "session-resources" / "sessions.json"

    if failure == "invalid_json":
        ledger.write_text("{", encoding="utf-8")
    else:
        original_read_text = Path.read_text

        def read_text(path, *args, **kwargs):
            if path == ledger:
                raise PermissionError("resource ledger is unreadable")
            return original_read_text(path, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", read_text)

    with pytest.raises(exception_type):
        session_registry.held_resources(tmp_path)


def test_held_resources_does_not_take_writer_lock(tmp_path, monkeypatch):
    session_registry.reserve_resources(
        tmp_path,
        owner="owner-a",
        resources=[{
            "host": "192.0.2.10",
            "port": 1080,
            "protocol": "tcp",
        }],
    )

    ownership = create_autospec(
        session_registry.ownership,
        side_effect=AssertionError("reader tried to acquire writer lock"),
    )
    monkeypatch.setattr(session_registry, "ownership", ownership)

    assert session_registry.held_resources(tmp_path) == [
        ["192.0.2.10", 1080],
    ]
    ownership.assert_not_called()
