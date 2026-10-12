"""The model-facing layer: shared transport and agent-owned wire formats.

* :mod:`agents._model.client` - the shared model client.
* :mod:`agents._model.contract` - exchange objects and error names.
* :mod:`agents.planner.io` - the planner's input/output wire format.
* :mod:`agents.executor.driver` - the single-task execution loop.
* :mod:`agents.executor.prompts` - executor prompts and budget hints.
* :mod:`agents.verifier.service` - node verification and evidence checks.

Package import does not eagerly load these modules.
"""
