import openai
import json
from uuid import uuid4

session_id = f"flow-live-{uuid4().hex[:8]}"
client = openai.OpenAI(
    base_url="http://localhost:8080/v1",
    default_headers={"X-Session-Id": session_id},
)
print(f"Session ID: {session_id}")

tools = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get weather for a city",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_population",
            "description": "Get population of a city",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"]
            }
        }
    }
]

messages = [
    {"role": "system", "content": "You have weather and population tools. Use them."},
    {"role": "user", "content": "Compare Tokyo and London — weather and population."},
]

print("Turn 1: request with tools...")
r = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=messages,
    tools=tools,
    max_tokens=300,
)

if r.choices[0].message.tool_calls:
    all_tool_calls = list(r.choices[0].message.tool_calls)
    for tc in all_tool_calls:
        print(f"  Tool: {tc.function.name}({tc.function.arguments})")

    # Use one tool-call chain for deterministic follow-up validation.
    tc = all_tool_calls[0]
    assistant_tool_calls = [
        {
            "id": tc.id,
            "type": "function",
            "function": {
                "name": tc.function.name,
                "arguments": tc.function.arguments,
            },
        }
    ]
    messages.append(
        {
            "role": "assistant",
            "content": r.choices[0].message.content or "",
            "tool_calls": assistant_tool_calls,
        }
    )
    messages.append({
        "role": "tool",
        "tool_call_id": tc.id,
        "name": tc.function.name,
        "content": json.dumps({"result": f"Mock data for {tc.function.arguments}"}),
    })

    print("Turn 2: with tool results...")
    r2 = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        tools=tools,
        max_tokens=300,
    )
    msg2 = r2.choices[0].message
    text = msg2.content if isinstance(msg2.content, str) and msg2.content else ""
    if text:
        print(f"  Response: {text[:100]}...")
    elif msg2.tool_calls:
        print(f"  Response: model returned {len(msg2.tool_calls)} tool call(s) on turn 2")
    elif getattr(msg2, "refusal", None):
        print(f"  Response: refusal -> {str(msg2.refusal)[:100]}...")
    else:
        print("  Response: empty content (no text/tool_calls)")
else:
    print("  No tool calls (model decided not to use tools)")

print("\n→ Проверь dashboard: Flow X-Ray tab")
print(f"  Выбери сессию '{session_id}' в dropdown → должен появиться SVG граф")
