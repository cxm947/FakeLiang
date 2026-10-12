"""The graph side: read a compiled action graph and speak its vocabulary.

``parser`` reads a MulVAL TXT projection, ``terms`` speaks the fact vocabulary, ``cases`` selects
the case a node belongs to, ``rule_catalog`` holds the compiled rule descriptions, ``protocol``
folds a service spelling onto its transport, ``rehydrate`` loads a document into the node view
the execution flow consumes, ``paths`` resolves relative paths from the checkout root, and ``files``
writes one file atomically.
"""

from .parser import GraphFormatError, read_text, read_txt

__all__ = ["GraphFormatError", "read_text", "read_txt"]
