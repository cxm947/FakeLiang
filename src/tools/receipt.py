"""One receipt contract for every execution surface.

Three facts were previously folded into ``effect_known``: whether the transport
brought a terminal receipt back, whether the command itself succeeded, and whether
the call timed out. They are different questions:

* ``receipt_confirmed`` -- a terminal receipt exists for this request. A failed
  command still has a confirmed receipt; an unanswered write does not.
* ``command_succeeded`` -- the surface's own success flag, when it reports one.
  ``None`` means the surface cannot tell (for example a meterpreter console has
  no process exit status).
* ``effect_known`` -- legacy aggregate kept for stored evidence and older
  consumers: the receipt is confirmed and the command did not clearly fail.

New consumers that only need "did this round produce something the model can
judge" read ``receipt_confirmed``. Delivery gates that require the command to
have worked read ``command_succeeded`` (or the legacy ``effect_known``).
"""

from __future__ import annotations


def make_receipt(*, confirmed, response=None, succeeded=None, timed_out=False,
                 transport_error=False, **fields):
    """Build one receipt from transport facts.

    ``confirmed`` is what the surface observed, never what the caller hopes.
    A transport error cancels confirmation, even when the caller also passed a
    truthy ``confirmed`` by mistake. A command-budget timeout does not: the
    surface returned a terminal receipt (for example exit 124), and that receipt
    is exactly what the model has to judge.
    """
    body = dict(response or {})
    transport_error = bool(transport_error or body.get("transport_error"))
    receipt_confirmed = bool(confirmed) and not transport_error
    if succeeded is None:
        code = body.get("return_code")
        if type(code) is int:
            succeeded = code == 0
    if not receipt_confirmed:
        succeeded = None
    # ``effect_known`` answers "do we know what happened", not "did it work".
    # Command success travels separately so a failed-but-confirmed command still
    # reaches the model's assessment.
    value = {"effect_known": receipt_confirmed,
             "receipt_confirmed": receipt_confirmed,
             "command_succeeded": succeeded,
             "response": body}
    value.update(fields)
    return value


def is_confirmed(value):
    """Read confirmation from a new receipt or a stored legacy one."""
    if not isinstance(value, dict):
        return False
    if "receipt_confirmed" in value:
        return bool(value["receipt_confirmed"])
    return bool(value.get("effect_known"))


__all__ = ["is_confirmed", "make_receipt"]
