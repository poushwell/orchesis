# Configuration Reference

`orchesis.yaml` is the runtime control file for proxy behavior.

## Core sections

- `proxy` - host, port, timeouts, workers
- `upstream` - provider endpoints and pass-through behavior
- `security` - detection, filtering, policy controls
- `budget` - spend limits and alerts
- `cascade` - routing and fallback strategies
- `recording` - session capture settings
- `dashboard` - dashboard availability and controls

For complete examples, see:

- `config/orchesis_example.yaml`
- `config/orchesis_openclaw.yaml`

