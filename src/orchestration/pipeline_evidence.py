"""Read projections of the existing checkpoints; never a second execution path."""

from pathlib import Path

from run_action import save


def collect(value, keys):
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in keys and isinstance(item, (dict, list)):
                found.append({key: item})
            elif isinstance(item, (dict, list)):
                found.extend(collect(item, keys))
    elif isinstance(value, list):
        for item in value:
            found.extend(collect(item, keys))
    return found


class PipelineEvidence:
    def __init__(self, directory, service):
        self.directory, self.service = Path(directory), service
        self.number = 1

    @property
    def round_directory(self):
        return self.directory / "rounds" / f"{self.number:03d}"

    def __call__(self, state):
        save(self.directory / "state.json", state)
        rows = {row["number"]: row for row in state["rounds"]}
        current = state.get("current", {})
        post_progress = self.service.post.inspect(state["run_id"])
        if current:
            rows[current["number"]] = current
        sessions = [row.model_dump(mode="json") for row in
                    self.service.sessions.list_for_run(state["run_id"])]
        save(self.directory / "sessions" / "registry.json", sessions)
        tunnels = []
        for directive in state["input"]["tunnels"]:
            record = self.service.tunnels.registry.by_operation(state["run_id"], directive["operation_id"])
            if record and record.tunnel_id not in {r["tunnel_id"] for r in tunnels}:
                tunnels.append(record.model_dump(mode="json"))
        save(self.directory / "tunnels" / "registry.json", tunnels)
        # Completed rounds are immutable; only the active round needs refreshing.
        for number, row in rows.items():
            folder = self.directory / "rounds" / f"{number:03d}"
            if number != current.get("number") and (folder / "state" / "round.json").exists():
                continue
            save(folder / "state" / "round.json", {**row, "failure": state["failure"]})
            pending_post = post_progress["state"].get("current", {})
            if pending_post.get("attempt_id") == row.get("action_id"):
                save(folder / "state" / "post-handoff.json", post_progress)
                save(folder / "sessions" / "closeout-request.json", pending_post.get("closeout_request"))
            for stage in ("planner", "pre", "action", "post"):
                view = row.get(stage)
                if stage == "post" and view is None and pending_post.get("attempt_id") == row.get("action_id"):
                    try:
                        view = self.service.post.post_service.inspect(pending_post["post_thread_id"])
                    except KeyError:
                        pass
                if view is None and row.get(stage + "_id"):
                    try:
                        view = getattr(self.service, stage).inspect(row[stage + "_id"])
                    except (KeyError, ValueError):
                        pass
                if view:
                    save(folder / "state" / f"{stage}.json", view)
                    child = view.get("state", view)
                    model_rows = collect(child, {"calls"}) if stage == "planner" else collect(
                        {key: child.get(key) for key in ("current", "history", "records", "attempts")},
                        {"request", "invalid_request", "generation", "judgment", "judgments", "model_judgments"})
                    save(folder / "models" / f"{stage}.json",
                         model_rows)
                    save(folder / "execution" / f"{stage}.json", collect(view, {"observation", "action_evidence"}))
            save(folder / "sessions" / "registry.json", sessions)
            save(folder / "sessions" / "registration.json", row.get("session"))
            save(folder / "tunnels" / "registry.json", tunnels)
            save(folder / "tunnels" / "operations.json", [r for r in state["tunnel_results"]
                if r["directive"]["node_id"] == row.get("node_id")])
        self.number = len(state["rounds"]) + 1
