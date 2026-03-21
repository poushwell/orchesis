# orchesis-context

Orchesis Context Engine Plugin for Node.js.

## Install

```bash
npm install orchesis-context
```

## Usage

```javascript
const { OrchesisContext, OrchesisMiddleware } = require("orchesis-context");

const ctx = new OrchesisContext({ proxyUrl: "http://localhost:8090" });
const quality = await ctx.checkQuality([]);
console.log(quality);
```

Provides:
- `OrchesisContext` for quality and metrics calls
- `OrchesisMiddleware` for response headers in Express/Node pipelines
