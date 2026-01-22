# OpenCode Agent Guidelines

## Build, Test, and Lint Commands

### Root Commands

- `bun dev` - Run opencode in packages/opencode
- `bun turbo typecheck` - Typecheck all packages
- `bun prepare` - Setup husky git hooks

### Package Commands (packages/opencode)

- `bun dev` - Run opencode with browser condition
- `bun test` - Run all tests
- `bun test --filter <pattern>` - Run specific tests
- `bun run script/build.ts` - Build the project
- `bun run --prettier --write src/**/*.ts` - Format code

### Running Single Tests

```bash
# Run a specific test file
bun test test/util/iife.test.ts

# Run tests matching a pattern
bun test --filter "tool.bash"
```

### Default Branch

The default branch is `dev`

## Code Style Guidelines

### Imports

- Use alias imports: `import { Log } from "@/util/log"`
- Alias `@/*` maps to `./src/*`
- Third-party: `import z from "zod"` or `import { expect, test } from "bun:test"`
- Relative imports for local files: `import { File } from "../file"`

### Formatting

- **No semicolons** (configured in prettier)
- Print width: 120 characters
- Use `bun run --prettier --write` to format

### Types

- Use Zod for runtime schema validation
- Define types with Zod: `const Schema = z.object({ ... })`
- Infer types: `type SchemaType = z.infer<typeof Schema>`
- Export schemas with `.meta()` for API documentation

### Naming Conventions

- **Prefer single word names**: `const log`, `const file`, `const result`
- Namespace pattern: `export namespace ModuleName { ... }`
- Interface and type exports inside namespaces
- Upper case for constants: `const MAX_RETRY = 3`

### Code Patterns

#### Prefer const over let

```ts
// Good
const result = condition ? 1 : 2

// Bad
let result
if (condition) result = 1
else result = 2
```

#### Early returns

```ts
function foo() {
  if (condition) return 1
  return 2
}
```

#### Avoid else statements - use early returns instead

#### Error handling

- Use `throw new Error("message", { cause })` to chain errors
- Prefer throwing over try/catch when possible
- Catch expected errors with `.catch(() => {})` or `.nothrow()`

#### Logging

```ts
const log = Log.create({ service: "module.name" })
log.info("message", { key: value })
log.error("error", { error })
const timer = log.time("operation")
// ... do work
timer.stop()
```

#### Using Bun APIs

- `Bun.file(path)` for file operations
- `Bun.write(path, content)` for writing files
- `$`command`` for shell commands via bun
- `await Bun.$`command``.quiet().nothrow().text()` for safe shell commands

#### File paths

- `path.join(...)` for joining paths
- `path.relative(from, to)` for relative paths
- Always handle path normalization for cross-platform

### Using Parallel Tools

Always use parallel tool calls when operations are independent. Multiple tools in a single message execute concurrently for better performance.

### Testing

- Use `bun:test` framework: `import { describe, test, expect } from "bun:test"`
- Organize tests: `describe("module", () => { test("case", () => {}) })`
- Test setup: `await Instance.provide({ directory, fn: async () => {} })`
- Mock context objects for tool testing

### State Management

- Use `Instance.state()` for cached state
- State is lazy-loaded on first access

### Zod Validation

- Define schemas with `z.object()`, `z.enum()`, `z.string()`, etc.
- Use `.optional()` for optional fields
- Validate input: `schema.parse(input)`
- Handle errors: `error instanceof z.ZodError`

### Async Patterns

- Use `for await` for async iteration
- `await Promise.all()` for concurrent operations
- `using` keyword with `Symbol.dispose` for cleanup

### Tool Definition Pattern

```ts
export const ToolName = Tool.define("id", {
  description: "...",
  parameters: z.object({ ... }),
  async execute(params, ctx) {
    // Implementation
    return { title: "...", metadata: {}, output: "..." }
  },
})
```

### Bus Events

```ts
export const Event = {
  Name: BusEvent.define("event.name", z.object({ ... })),
}
```

### Avoid

- Comments (unless asked)
- Unnecessary destructuring: use `obj.prop` instead of `const { prop } = obj`
- `any` type - use proper TypeScript types
- Try/catch where early returns suffice
