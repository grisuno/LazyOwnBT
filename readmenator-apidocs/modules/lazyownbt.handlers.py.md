# `lazyownbt.handlers`

> Source: [lazyownbt/handlers.py:1](../../lazyownbt/handlers.py#L1) | language `py` | coverage 37.5% | [API index](../index.md)

Handlers de acciones: código de aplicación, no shell.

Cada handler es una función Python pura que recibe los parámetros validados
por el ActionRegistry. Si necesita lanzar subprocesos, debe hacerlo de forma
segura (lista cerrada de binarios + argumentos en array, nunca string).

## Contents

- **Functions:** [`handle_resp_block_ip`](#handle_resp_block_ip), [`handle_resp_kill_proc`](#handle_resp_kill_proc), [`handle_net_scan`](#handle_net_scan), [`handle_fim_scan`](#handle_fim_scan), [`handle_lazynmap`](#handle_lazynmap), [`handle_ai_playbook`](#handle_ai_playbook), [`build_default_handlers`](#build_default_handlers)

## Functions

<a id="handle_resp_block_ip"></a>

### `handle_resp_block_ip`

`function` | [lazyownbt/handlers.py:32](../../lazyownbt/handlers.py#L32)

```python
def handle_resp_block_ip(ip_address: str = '', interface: str = 'INPUT', **_extra: Any) -> str
```

Stub seguro.

En un despliegue real invocaría iptables con argv.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `ip_address` | `str` | `''` |  |
| `interface` | `str` | `'INPUT'` |  |
| `**_extra` | `Any` |  |  |

**Returns:** `str`

**Raises**

- `RuntimeError`: (raised in the body, not documented)
- `ValueError`: (raised in the body, not documented)

---

<a id="handle_resp_kill_proc"></a>

### `handle_resp_kill_proc`

`function` | [lazyownbt/handlers.py:52](../../lazyownbt/handlers.py#L52)

```python
def handle_resp_kill_proc(pid: int = 0, signal: int = 15, **_extra: Any) -> str
```

Stub seguro.

En un despliegue real enviaría la señal al PID.

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `pid` | `int` | `0` |  |
| `signal` | `int` | `15` |  |
| `**_extra` | `Any` |  |  |

**Returns:** `str`

**Raises**

- `ValueError`: (raised in the body, not documented)

---

<a id="handle_net_scan"></a>

### `handle_net_scan`

`function` | [lazyownbt/handlers.py:64](../../lazyownbt/handlers.py#L64)

```python
def handle_net_scan(**_extra: Any) -> str
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `**_extra` | `Any` |  |  |

**Returns:** `str`

---

<a id="handle_fim_scan"></a>

### `handle_fim_scan`

`function` | [lazyownbt/handlers.py:68](../../lazyownbt/handlers.py#L68)

```python
def handle_fim_scan(**_extra: Any) -> str
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `**_extra` | `Any` |  |  |

**Returns:** `str`

---

<a id="handle_lazynmap"></a>

### `handle_lazynmap`

`function` | [lazyownbt/handlers.py:72](../../lazyownbt/handlers.py#L72)

```python
def handle_lazynmap(target: str = '', **_extra: Any) -> str
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `target` | `str` | `''` |  |
| `**_extra` | `Any` |  |  |

**Returns:** `str`

**Raises**

- `ValueError`: (raised in the body, not documented)

---

<a id="handle_ai_playbook"></a>

### `handle_ai_playbook`

`function` | [lazyownbt/handlers.py:78](../../lazyownbt/handlers.py#L78)

```python
def handle_ai_playbook(scenario: str = '', **_extra: Any) -> str
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `scenario` | `str` | `''` |  |
| `**_extra` | `Any` |  |  |

**Returns:** `str`

**Raises**

- `ValueError`: (raised in the body, not documented)

---

<a id="build_default_handlers"></a>

### `build_default_handlers`

`function` | [lazyownbt/handlers.py:84](../../lazyownbt/handlers.py#L84)

```python
def build_default_handlers() -> Dict[str, Callable[..., Any]]
```

**Returns:** `Dict[str, Callable[..., Any]]`

---
