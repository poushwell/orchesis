from orchesis import OrchesisClient
import openai

sdk = OrchesisClient("http://localhost:8080")
ai = openai.OpenAI(base_url="http://localhost:8080/v1")

# Создать эксперимент
exp = sdk.create_experiment(
    name="Mini vs Standard",
    variants=[
        {"name": "mini", "weight": 0.5, "model_override": "gpt-4o-mini"},
        {"name": "standard", "weight": 0.5, "model_override": "gpt-4o"},
    ],
    split_strategy="round_robin",
)
print(f"Created: {exp.get('experiment_id', exp)}")

exp_id = exp.get("experiment_id", "")
if exp_id:
    sdk.start_experiment(exp_id)
    print("Started!")

    for i in range(6):
        r = ai.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": f"What is {i*7}?"}],
            max_tokens=20,
        )
        print(f"  [{i+1}] Model: {r.model}")

    results = sdk.get_experiment_results(exp_id)
    print(f"Results: {results}")
    sdk.stop_experiment(exp_id)
    print("Stopped!")