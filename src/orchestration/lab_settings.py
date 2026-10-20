"""Deployment-declared lab settings shared by the CLI entry points.

Kept separate from ``pipeline_lab`` because that module imports ``run_action`` for the
rollback helper, and the entry points import this module: a shared constant here avoids a
circular import.
"""


def lock_name(lab):
    """The deployment's own lock name; one lab per name, never a global constant."""
    return str((lab or {}).get("lock") or "action:vmware-lab")
