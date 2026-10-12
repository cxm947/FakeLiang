"""Verify synchronous official PostgreSQL checkpoint persistence.

The optional extras are imported late on purpose: every script here has to answer `--help` on a
machine where they are not installed (tests/test_project_layout.py runs them from another
directory), and a missing extra should say what to install rather than fail at import time.
"""
import argparse
import os

MISSING_EXTRA = ("the postgres memory check needs the optional extra: install "
                 "langgraph-checkpoint-postgres and psycopg[binary,pool]")


def graph(saver):
    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, MessagesState, StateGraph

    builder = StateGraph(MessagesState)
    builder.add_node("remember", lambda state: {
        "messages": [AIMessage(content="saved-reply", id="reply")]})
    builder.add_edge(START, "remember")
    builder.add_edge("remember", END)
    return builder.compile(checkpointer=saver)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args()
    try:
        from langchain_core.messages import HumanMessage
        from langgraph.checkpoint.postgres import PostgresSaver
    except ModuleNotFoundError as error:
        raise SystemExit(MISSING_EXTRA + " (" + str(error) + ")")
    dsn = os.environ["AGV_MEMORY_DATABASE_URL"]
    config = {"configurable": {
        "thread_id": os.environ["AGV_MEMORY_SMOKE_THREAD"]},
        "recursion_limit": 3}
    if not args.read_only:
        with PostgresSaver.from_conn_string(dsn) as saver:
            saver.setup()
            result = graph(saver).invoke(
                {"messages": [HumanMessage(content="saved-request", id="request")]},
                config=config, durability="sync")
            assert result["messages"][-1].content == "saved-reply"
    with PostgresSaver.from_conn_string(dsn) as saver:
        state = graph(saver).get_state(config)
        messages = state.values["messages"]
        assert [m.content for m in messages] == ["saved-request", "saved-reply"]
        assert not state.next
    print("postgres memory roundtrip: PASS")


if __name__ == "__main__":
    main()
