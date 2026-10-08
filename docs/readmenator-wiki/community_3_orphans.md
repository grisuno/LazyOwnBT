# orphans

*Community 3 | 12 files | cohesion 0.00*

## Definition

This community groups 12 file(s) rooted at `tests` with dominant language py (cohesion 0.00). Central symbols: `AUTH`, `Alert`, `Cyan`, `Database`, `DetectionEngine`, `Fg`, `FgColor`, `FileIntegrityMonitor`. Core file: `app.py` (193 symbols). Documented purpose: LazyOwn BlueTeam Framework Una herramienta monolítica de seguridad defensiva para detección de amenazas, respuesta a incidentes y endurecimiento de sistemas Lin.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `app.py` | py | utility | 193 | yes |
| `install.sh` | sh | utility | 0 | no |
| `lazyownbt/__init__.py` | py | utility | 0 | yes |
| `lazyownbt/detection.py` | py | utility | 17 | yes |
| `skills/lazyownbt_mcp.py` | py | utility | 13 | yes |
| `static/js/auth.js` | js | utility | 1 | yes |
| `static/js/commands.js` | js | utility | 3 | yes |
| `static/js/table-filter.js` | js | utility | 2 | yes |
| `tests/test_command_execution_bdd.py` | py | testing | 0 | yes |
| `tests/test_configuration_bdd.py` | py | testing | 0 | yes |
| `tests/test_production_bdd.py` | py | testing | 0 | yes |
| `tests/test_secrets_bdd.py` | py | testing | 0 | yes |

## Key Symbols

- `Fg` (class, `app.py:48`) `class Fg` - Color foreground (compat). Mapea al enum `cmd2.styles.Color`.
- `style` (method, `app.py:75`) `def style(text, fg, bold)` - Equivalente funcional de la antigua `cmd2.style(text, fg=..., bold=...)`.
- `replace_command_placeholders` (method, `app.py:209`) `def replace_command_placeholders(command, params)` - Replace placeholders in a command string with values from a params dictionary,
- `replace_match` (method, `app.py:227`) `def replace_match(match)`
- `FgColor` (class, `app.py:232`) `class FgColor`
- `Cyan` (class, `app.py:235`) `class Cyan(FgColor)`
- `Red` (class, `app.py:238`) `class Red(FgColor)`
- `sanitize_content` (method, `app.py:241`) `def sanitize_content(text)` - Sanitize text to ensure it's safe for Markdown rendering.
- `RAGManager` (class, `app.py:253`) `class RAGManager` - Manages RAG functionality with CAG caching for document processing and querying.
- `__init__` (method, `app.py:256`) `def __init__(self, model_name, cache_size)`
- `initialize_cache_table` (method, `app.py:269`) `def initialize_cache_table(self)` - Initialize SQLite table for persistent cache.
- `get_cache_key` (method, `app.py:282`) `def get_cache_key(self, content)` - Generate a cache key from content using SHA-256.
- `load_existing_vectorstore` (method, `app.py:286`) `def load_existing_vectorstore(self)` - Load existing vectorstore if available.
- `ollama_llm` (method, `app.py:300`) `def ollama_llm(self, question, context)` - Query LLM with context using Ollama.
- `process_file_to_rag` (method, `app.py:315`) `def process_file_to_rag(self, file_path)` - Process a file, add it to the RAG knowledge base, and cache embeddings.
- `query_rag` (method, `app.py:374`) `def query_rag(self, question)` - Query the RAG system with caching.
- `invalidate_cache` (method, `app.py:414`) `def invalidate_cache(self, file_path)` - Invalidate cache entries for a specific file.
- `get_knowledge_base_stats` (method, `app.py:433`) `def get_knowledge_base_stats(self)` - Get statistics about the knowledge base and cache.
- `Database` (class, `app.py:459`) `class Database` - Clase para manejar la base de datos SQLite.
- `__init__` (method, `app.py:462`) `def __init__(self, db_path)`
- `initialize` (method, `app.py:468`) `def initialize(self)` - Inicializa la conexión a la base de datos y crea las tablas si no existen.
- `execute` (method, `app.py:554`) `def execute(self, query, params)` - Ejecuta una consulta SQL y devuelve los resultados.
- `insert` (method, `app.py:564`) `def insert(self, query, params)` - Inserta datos en la base de datos y devuelve el ID del último registro.
- `close` (method, `app.py:575`) `def close(self)` - Cierra la conexión a la base de datos.
- `execute` (method, `app.py:582`) `def execute(self, query, params)` - Ejecuta una consulta SQL y devuelve los resultados.
- `insert` (method, `app.py:592`) `def insert(self, query, params)` - Inserta datos en la base de datos y devuelve el ID del último registro.
- `close` (method, `app.py:603`) `def close(self)` - Cierra la conexión a la base de datos.
- `Alert` (class, `app.py:609`) `class Alert` - Clase para representar y manejar alertas.
- `__init__` (method, `app.py:614`) `def __init__(self, alert_type, details, severity)`
- `to_dict` (method, `app.py:620`) `def to_dict(self)` - Convierte la alerta a diccionario.

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 0
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 0 <-> 3 (strength 0.5): Inferred shared context (language py) with no import path between community 0 (lazyownbt: web) and community 3 (orphans).
- [INFERRED] shares_context community 1 <-> 3 (strength 0.5): Inferred shared context (language py) with no import path between community 1 (lazyownbt: main) and community 3 (orphans).
- [INFERRED] shares_context community 2 <-> 3 (strength 0.5): Inferred shared context (language py) with no import path between community 2 (lazyownbt: security) and community 3 (orphans).

## Risks

- [taint high] `app.py` -> `app.py` via `subprocess` (0 hops)
- [taint medium] `app.py` -> `app.py` via `requests` (0 hops)
- [taint high] `lazyownbt/detection.py` -> `lazyownbt/detection.py` via `subprocess` (0 hops)
- [taint high] `skills/lazyownbt_mcp.py` -> `skills/lazyownbt_mcp.py` via `subprocess` (0 hops)

## Open Questions

- Why do 1 file(s) lack file-level docs (e.g. `install.sh`)? What purpose do they serve?
- Is the dangerous import `subprocess` in `app.py` still required, or can it be isolated?
- What would break if the most connected file in orphans changed?
- Should orphans be split, given cohesion 0.00?

## Sources

- `app.py`
- `install.sh`
- `lazyownbt/__init__.py`
- `lazyownbt/detection.py`
- `skills/lazyownbt_mcp.py`
- `static/js/auth.js`
- `static/js/commands.js`
- `static/js/table-filter.js`
- `tests/test_command_execution_bdd.py`
- `tests/test_configuration_bdd.py`
- `tests/test_production_bdd.py`
- `tests/test_secrets_bdd.py`
