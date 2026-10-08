# Architecture

## Internal Dependencies

- `lazyownbt/handlers.py` -> `lazyownbt/actions.py`
- `lazyownbt/web.py` -> `lazyownbt/actions.py`
- `lazyownbt/web.py` -> `lazyownbt/audit.py`
- `lazyownbt/web.py` -> `lazyownbt/config.py`
- `lazyownbt/web.py` -> `lazyownbt/handlers.py`
- `lazyownbt/web.py` -> `lazyownbt/security.py`
- `main.py` -> `lazyownbt/config.py`
- `main.py` -> `lazyownbt/web.py`
- `tests/conftest.py` -> `lazyownbt/config.py`
- `tests/conftest.py` -> `lazyownbt/security.py`
- `tests/conftest.py` -> `lazyownbt/web.py`
- `tests/test_command_execution.py` -> `lazyownbt/actions.py`
- `tests/test_command_execution.py` -> `lazyownbt/web.py`
- `tests/test_configuration.py` -> `lazyownbt/config.py`
- `tests/test_production.py` -> `lazyownbt/config.py`
- `tests/test_production.py` -> `lazyownbt/web.py`
- `tests/test_security.py` -> `lazyownbt/config.py`
- `tests/test_security.py` -> `lazyownbt/security.py`

## External Imports

- `app.py` -> argparse, cachetools, chromadb, cmd2, cmd2.styles, collections, concurrent.futures, csv, datetime, grp, hashlib, joblib, json, langchain_chroma, langchain_community.document_loaders, langchain_ollama, langchain_text_splitters, logging, lupa, ollama, os, pandas, pathlib, platform, psutil, pwd, queue, re, requests, rich, rich.console, rich.markdown, rich.panel, shutil, signal, sklearn.feature_extraction.text, socket, sqlite3, subprocess, sys, tabulate, tempfile, threading, time, typing, warnings, watchdog.events, watchdog.observers, yaml
- `lazyownbt/actions.py` -> __future__, dataclasses, typing
- `lazyownbt/audit.py` -> __future__, contextlib, dataclasses, datetime, json, logging, pathlib, sqlite3, threading, time, typing
- `lazyownbt/config.py` -> __future__, bcrypt, dataclasses, dotenv, os, pathlib, secrets, sys, typing
- `lazyownbt/detection.py` -> __future__, dataclasses, datetime, json, logging, os, pathlib, re, sqlite3, subprocess, threading, time, typing
- `lazyownbt/handlers.py` -> __future__, os, re, socket, subprocess, typing
- `lazyownbt/security.py` -> __future__, bcrypt, logging, re, typing
- `lazyownbt/web.py` -> __future__, argparse, flask, flask_jwt_extended, flask_talisman, logging, os, pathlib, typing
- `main.py` -> __future__, argparse, datetime, flask, json, logging, os, pathlib, sqlite3, typing
- `skills/lazyownbt_mcp.py` -> asyncio, datetime, fcntl, json, mcp, mcp.server, mcp.server.stdio, os, pathlib, pty, re, select, signal, sqlite3, struct, subprocess, sys, termios, time, typing
- `tests/conftest.py` -> __future__, ast, bcrypt, flask_jwt_extended, json, logging, os, pathlib, pytest, pytest_bdd, re, sys, tomllib
- `tests/test_command_execution.py` -> __future__, json, pathlib, pytest, re
- `tests/test_command_execution_bdd.py` -> __future__, pytest_bdd
- `tests/test_configuration.py` -> __future__, ast, pathlib, pytest, re, sys, tomllib
- `tests/test_configuration_bdd.py` -> __future__, pytest_bdd
- `tests/test_production.py` -> __future__, logging, pathlib, pytest
- `tests/test_production_bdd.py` -> __future__, pytest_bdd
- `tests/test_secrets_bdd.py` -> __future__, pytest_bdd
- `tests/test_security.py` -> __future__, bcrypt, pathlib, pytest, re
