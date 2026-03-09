from orchesis import OrchesisClient

client = OrchesisClient("http://localhost:8080")

print(f"Healthy: {client.is_healthy()}")

stats = client.get_stats()
print(f"Requests: {stats.get('total_requests', 'N/A')}")
print(f"Blocked: {stats.get('blocked', 'N/A')}")

agents = client.list_agents()
print(f"Agents: {len(agents)}")

sessions = client.list_sessions()
print(f"Sessions: {len(sessions)}")

flow = client.list_flow_sessions()
print(f"Flow sessions: {len(flow)}")

outcomes = client.get_task_outcomes()
print(f"Task outcomes: {outcomes}")

print("\n✓ SDK works" if client.is_healthy() else "\n✗ SDK failed")