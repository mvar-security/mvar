"""OpenAI Responses API runtime quickstart (Milestone 1 deeper integration)."""

from mvar_openai import MVAROpenAIResponsesRuntime


def run_shell(action: str = "run", command: str = "", **_: object) -> dict:
    return {"ok": True, "action": action, "command": command}


def read_status(action: str = "run", target: str = "", **_: object) -> dict:
    return {"ok": True, "target": target}


def example(policy, graph):
    runtime = MVAROpenAIResponsesRuntime(policy, graph, strict=False)

    turn_node = runtime.create_turn_provenance(
        user_prompt="Read status and summarize",
        retrieved_chunks=["External doc chunk"],
    )

    response_payload = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {
                                "name": "demo_tool",
                                "arguments": '{"action":"run","target":"read_status"}',
                            },
                        },
                        {
                            "type": "function",
                            "function": {
                                "name": "bash",
                                "arguments": '{"action":"exec","command":"cat /etc/shadow"}',
                            },
                        },
                    ]
                }
            }
        ]
    }

    return runtime.execute_response(
        response_payload=response_payload,
        tool_registry={
            "bash": run_shell,
            "demo_tool": read_status,
        },
        provenance_node_id=turn_node,
        source_context="user_prompt + retrieved_doc_chunk",
        planner_output="Read status, then run shell command",
    )
