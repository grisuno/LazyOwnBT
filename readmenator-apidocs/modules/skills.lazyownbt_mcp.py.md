# `skills.lazyownbt_mcp`

> Source: [skills/lazyownbt_mcp.py:1](../../skills/lazyownbt_mcp.py#L1) | language `py` | coverage 25.0% | [API index](../index.md)

LazyOwnBT MCP Server Exposes LazyOwnBT Blue Team framework capabilities as MCP tools for Claude Code.

Usage:
    python3 skills/lazyownbt_mcp.py

Configuration via environment variables:
    LAZYOWNBT_DIR     - Path to LazyOwnBT directory (default: parent of this file)
    LAZYOWNBT_CONFIG  - Path to config.json (default: <LAZYOWNBT_DIR>/config.json)

## Contents

- **Functions:** [`list_tools`](#list_tools), [`call_tool`](#call_tool), [`main`](#main)
- **Constants:** [`SKILLS_DIR`](#skills_dir), [`LAZYOWNBT_DIR`](#lazyownbt_dir), [`CONFIG_FILE`](#config_file), [`DB_PATH`](#db_path), [`REPORTS_DIR`](#reports_dir), [`QUARANTINE_DIR`](#quarantine_dir)

## Functions

<a id="list_tools"></a>

### `list_tools`

`function` `async` | [skills/lazyownbt_mcp.py:168](../../skills/lazyownbt_mcp.py#L168)

Decorators: `@server.list_tools()`

```python
async def list_tools() -> list[types.Tool]
```

**Returns:** `list[types.Tool]`

---

<a id="call_tool"></a>

### `call_tool`

`function` `async` | [skills/lazyownbt_mcp.py:864](../../skills/lazyownbt_mcp.py#L864)

Decorators: `@server.call_tool()`

```python
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `name` | `str` |  |  |
| `arguments` | `dict[str, Any]` |  |  |

**Returns:** `list[types.TextContent]`

---

<a id="main"></a>

### `main`

`function` `async` | [skills/lazyownbt_mcp.py:1431](../../skills/lazyownbt_mcp.py#L1431)

```python
async def main()
```

---

## Constants

<a id="skills_dir"></a>

### `SKILLS_DIR`

`constant` | [skills/lazyownbt_mcp.py:37](../../skills/lazyownbt_mcp.py#L37)

```python
SKILLS_DIR = Path(__file__).parent
```

---

<a id="lazyownbt_dir"></a>

### `LAZYOWNBT_DIR`

`constant` | [skills/lazyownbt_mcp.py:38](../../skills/lazyownbt_mcp.py#L38)

```python
LAZYOWNBT_DIR = Path(os.environ.get('LAZYOWNBT_DIR', str(SKILLS_DIR.parent)))
```

---

<a id="config_file"></a>

### `CONFIG_FILE`

`constant` | [skills/lazyownbt_mcp.py:39](../../skills/lazyownbt_mcp.py#L39)

```python
CONFIG_FILE = Path(os.environ.get('LAZYOWNBT_CONFIG', str(LAZYOWNBT_DIR / 'config.json')))
```

---

<a id="db_path"></a>

### `DB_PATH`

`constant` | [skills/lazyownbt_mcp.py:40](../../skills/lazyownbt_mcp.py#L40)

```python
DB_PATH = LAZYOWNBT_DIR / 'lazyown.db'
```

---

<a id="reports_dir"></a>

### `REPORTS_DIR`

`constant` | [skills/lazyownbt_mcp.py:41](../../skills/lazyownbt_mcp.py#L41)

```python
REPORTS_DIR = LAZYOWNBT_DIR / 'reports'
```

---

<a id="quarantine_dir"></a>

### `QUARANTINE_DIR`

`constant` | [skills/lazyownbt_mcp.py:42](../../skills/lazyownbt_mcp.py#L42)

```python
QUARANTINE_DIR = LAZYOWNBT_DIR / 'quarantine'
```

---
