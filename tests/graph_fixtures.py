"""Compile explicit source graphs for runtime tests."""

from graph.parser import Graph, Node
from graph.projector import project
from graph.rehydrate import load_document


def loaded_graph(node_rows, edges):
    nodes = {str(ref): Node(str(ref), description, kind, "0")
             for ref, description, kind in node_rows}
    graph = Graph(nodes, {(str(source), str(target)): "0" for source, target in edges})
    document = project(graph)
    order = {str(row[0]): index for index, row in enumerate(node_rows)}
    document["nodes"].sort(key=lambda row: order[row["id"]])
    return load_document(document)
