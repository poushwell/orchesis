import openai

client = openai.OpenAI(
    base_url="http://localhost:8080/v1",
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "What is 2+2? Answer in one word."},
    ],
    max_tokens=10,
)

print(f"Status: OK")
print(f"Model: {response.model}")
print(f"Response: {response.choices[0].message.content}")
print(f"Tokens: {response.usage.prompt_tokens} in / {response.usage.completion_tokens} out")
