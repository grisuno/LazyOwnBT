# `static/js/auth.js`

> Source: [static/js/auth.js:1](../../static/js/auth.js#L1) | language `js` | coverage 14.3% | [API index](../index.md)

LazyOwnBT — helpers comunes de autenticación en el cliente.

## Contents

- **Functions:** [`AUTH`](#auth)
- **Other Members:** [`get`](#get), [`set`](#set), [`clear`](#clear), [`requireOrRedirect`](#requireorredirect), [`fetch`](#fetch)

## Functions

<a id="auth"></a>

### `AUTH`

`function` `const` | [static/js/auth.js:6](../../static/js/auth.js#L6)

```javascript
const AUTH = (() =>
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `() =>` |  |  |  |

---

## Other Members

<a id="get"></a>

### `get`

`method` | [static/js/auth.js:9](../../static/js/auth.js#L9)

```javascript
get() { return sessionStorage.getItem(KEY) || null; },
```

---

<a id="set"></a>

### `set`

`method` | [static/js/auth.js:10](../../static/js/auth.js#L10)

```javascript
set(t) { sessionStorage.setItem(KEY, t); },
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `t` |  |  |  |

---

<a id="clear"></a>

### `clear`

`method` | [static/js/auth.js:11](../../static/js/auth.js#L11)

```javascript
clear() { sessionStorage.removeItem(KEY); },
```

---

<a id="requireorredirect"></a>

### `requireOrRedirect`

`method` | [static/js/auth.js:12](../../static/js/auth.js#L12)

```javascript
requireOrRedirect(loginUrl = "/login")
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `loginUrl` |  | `"/login"` |  |

---

<a id="fetch"></a>

### `fetch`

`method` `async` | [static/js/auth.js:16](../../static/js/auth.js#L16)

```javascript
async fetch(url, options = {})
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `url` |  |  |  |
| `options` |  | `{}` |  |

---
