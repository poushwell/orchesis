# Quickstart

## Install

```bash
pip install orchesis
```

## 1) Initialize project

```bash
orchesis init
```

This creates starter `policy.yaml` and `request.json`.

## 2) Write your first policy

```yaml
rules:
  - name: budget_limit
    max_cost_per_call: 1.0
  - name: file_access
    allowed_paths: ["/data", "/tmp"]
    denied_paths: ["/etc", "/root"]
```

## 3) Verify your first request

```bash
orchesis verify request.json --policy policy.yaml
```

Allow returns exit code `0`, deny returns `1`.

## 4) Run the synthetic fuzzer

```bash
orchesis fuzz --policy policy.yaml --count 1000 --seed 42
```

## 5) Verify formal invariants

```bash
orchesis invariants --policy policy.yaml
```

## 5-Minute setup checklist

- Install package
- Initialize files
- Add baseline policy rules
- Verify one safe and one unsafe request
- Run fuzzer and invariants before production rollout
