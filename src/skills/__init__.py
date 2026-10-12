"""Skill cards: where a card lives, how its face is read, and how a node finds it.

Modules, one job each:

* :mod:`skills.layout` - a folder name and a business id, translated by the release map;
* :mod:`skills.lean`   - the flat ``SKILL.md`` face (8 required fields + optional ``when``) and
  the knowledge body, read as-is;
* :mod:`skills.bind`   - a graph node's own fields onto the one card that declares them, or a
  named gap.
* :mod:`skills.bind_prompts` - the packaged system prompt for model tie selection.

Nothing is imported at package import time, so reading a card never loads the graph or the
runtime.
"""
