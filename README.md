# LazyOwnBT

![image](https://github.com/user-attachments/assets/45898b81-52fd-4785-afe3-bd1bdfa51fec)

```text
skills/:                                                                                                           
  ┌──────────────────┬────────────────────────────────────────────────────┐                                        
  │     Archivo      │                    Descripción                     │                                        
  ├──────────────────┼────────────────────────────────────────────────────┤
  │ lazyownbt_mcp.py │ Servidor MCP principal (~680 líneas)               │                                        
  ├──────────────────┼────────────────────────────────────────────────────┤
  │ mcp_config.json  │ Config lista para copiar a ~/.claude/settings.json │                                        
  └──────────────────┴────────────────────────────────────────────────────┘
                                                                                                                                                                                                                                           
  35 herramientas MCP expuestas, organizadas por categoría Blue Team:

  - Ejecución: run_command, discover_commands, command_help                                                        
  - Config: get_config, set_config                          
  - Amenazas: proc_scan, net_scan, net_conns, net_baseline, memory_scan                                            
  - Integridad (FIM): fim_baseline, fim_scan, add_critical_file                                                    
  - Logs: log_analyze, monitor_start                                                                               
  - Hardening: harden_audit_ssh, harden_system, check_security, audit_users                                        
  - Respuesta a incidentes: block_ip, quarantine_file, kill_process                                                
  - IA/ML: ai_status, ai_test, ai_feedback, ai_retrain      
  - RAG/LLM: rag_query, rag_add, rag_status, rag_search                                                            
  - Reportes: report_summary, report_processes, report_network, report_files, list_reports, read_report            
  - BD/Alertas: list_alerts, list_events, db_stats                                                                 
  - Patrones: list_patterns, add_suspicious_process, add_suspicious_port                                           
  - Hunting: redteam_hunt, sysinfo
                                                                                
```
LazyOwnBT es una herramienta de seguridad defensiva (Blue Team) diseñada para la detección de amenazas, análisis de logs, monitoreo de procesos y redes, verificación de integridad de archivos, endurecimiento del sistema, generación de informes y respuesta a incidentes en entornos Linux.

Esta herramienta está pensada para ser utilizada por equipos de seguridad, analistas de SOC y profesionales de ciberseguridad que buscan automatizar tareas de monitoreo y protección en sistemas operativos basados en Linux.

📌 Características Principales
🛡️ Integración de Inteligencia Artificial en LazyOwn BlueTeam
Hemos transformado LazyOwn BlueTeam en una plataforma defensiva avanzada con capacidad de detección inteligente, aprovechando el modelo de IA entrenado por LazyOwn RedTeam. Esta integración cierra el ciclo entre ofensa y defensa, permitiendo que el conocimiento del atacante (Red Team) sea usado directamente para fortalecer la detección del defensor (Blue Team).
Detección de Amenazas : Análisis avanzado de logs (/var/log/auth.log, /var/log/syslog, etc.) para detectar intentos de inicio de sesión fallidos, uso sospechoso de sudo, usuarios creados o eliminados.
Monitoreo de Procesos y Redes : Detección de procesos y conexiones sospechosas basadas en nombres comunes de malware, puertos peligrosos o comportamiento inusual.
Verificación de Integridad de Archivos (FIM) : Comparación de hashes de archivos críticos para identificar modificaciones no autorizadas.
Endurecimiento del Sistema (Hardening) : Auditoría de configuraciones seguras para servicios como SSH, firewall (ufw), kernel y más.
Respuesta a Incidentes : Bloqueo de IPs maliciosas, terminación de procesos sospechosos y escaneo de memoria en busca de cadenas peligrosas.
Generación de Informes : Resúmenes estructurados de alertas, hallazgos y recomendaciones de mitigación.
Módulos Modularizados : Arquitectura limpia con componentes reutilizables y fácil de extender.

🔧 ¿Qué Hemos Agregado?
1. Motor de Detección con IA
 - Un sistema que analiza comandos ejecutados en los logs.
 - Usa un modelo de RandomForest + TF-IDF entrenado con miles de comandos reales de Red Team.
 - Detecta comandos peligrosos, ofuscados o desconocidos que no coinciden con reglas simples.

🧰 Requisitos
- Python 3.8+
Dependencias listadas en requirements.txt
Sistemas operativos compatibles: Linux (Ubuntu, Debian, CentOS, RHEL, etc.)

🛡️ Autor
Gris Uno - @grisuno

Repositorio oficial: https://github.com/grisuno/LazyOwnBT.git

🚀 ¿Cómo Contribuir?
¡Las contribuciones son bienvenidas! Si deseas mejorar esta herramienta, corrige errores, añade módulos nuevos o mejoras la documentación, sigue estos pasos:

Haz un fork del repositorio.
Crea una rama nueva (git checkout -b feature/amazing-feature).
Realiza tus cambios y haz commit (git commit -m 'Add amazing feature').
Sube tu rama (git push origin feature/amazing-feature).
Abre un Pull Request describiendo tus cambios.

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV) 
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/grisuno/LazyOwnBT)

<!-- readmenator-kb-link -->
## Knowledge Base

This project has been analyzed by [ReadMenator](https://github.com/grisuno/ReadMenator),
a zero-token polyglot static analysis tool. Regenerate with
`pip install readmenator && readmenator . --rebuild`. Analysis outputs:

- **[KNOWLEDGE_BASE.md](./KNOWLEDGE_BASE.md)** -- Full architecture reference with all
  classes, functions, imports, dependency graphs, UML class diagrams, security
  audit findings, community analysis, taint paths, hotspots, cycles, and more.
- **[readmenator-agent/](./readmenator-agent/)** -- Agent-friendly, grep-optimized index.
  - `INDEX.md` -- Quick reference: what each file does
  - `SYMBOLS.md` -- Every symbol with file:line
  - `ARCHITECTURE.md` -- Internal dependency pairs + external imports
  - `API.md` -- Public function contracts
  - `GOTCHAS.md` -- Change warnings (blast radius, cycles, hotspots)
  - `SECURITY.md` -- Findings by severity with fix hints
  - `MEMORY.md` -- Rules, workflow, style, deliverables, session log
  - `MANIFEST.json` -- Freshness (git_commit + source_fingerprint) + read order
  - `KB_<subsystem>.md` -- Per-subsystem context
  - `recipes/*.md` -- Grounded task guides (add-function, fix-cycle, ...)
- **[readmenator-wiki/](./readmenator-wiki/)** -- Navigable wiki (start here for the big picture).
  - `index.md` -- Entry point: overview, reading order, god nodes, connections
  - `community_*.md` -- One synthesis page per code community
  - `connections.json` -- Typed bridges between communities
  - `queries.md` -- Suggested questions + answer log
  - `REPORT.md` -- Honest audit: coverage, confidence, limits
- **[readmenator-graphrag/](./readmenator-graphrag/)** -- Zero-token GraphRAG index.
  - `index.json` + `REPORTS.md` -- Query with `readmenator . ask "<question>"`
- **[readmenator-apidocs/](./readmenator-apidocs/)** -- API reference (Sphinx/Doxygen style).
  - `index.md` + `modules/*.md` -- Signatures, parameters, returns, raises, examples, call graphs
  - `architecture.md` -- Tiered architecture + execution flows (control flow, call tree, sequence)
  - `classes.md`, `genindex.md`, `COVERAGE.md` -- Hierarchy, A-Z index, doc coverage + warnings
  - `index.html` + `api/` -- Offline searchable browser and machine-readable model (`api/index.json`, `api/modules/*.jsonl` one entity per line)
- **[readmenator-maps/](./readmenator-maps/)** -- Interactive gallery (`index.html`).
  - 5 system maps: architecture, workflow, sequence, dataflow, lifecycle
  - `graph-force.html` -- Force-graph explorer (2D/3D, reach, paths, lenses)
  - `graph-bundle.html` -- Edge bundle explorer (circle + sphere)
  - `components.html` -- Component diagrams
- **[docs/](./docs/)** -- Static site (GitHub Pages ready).
  - Gallery copy + `llms.txt` (agent entry point) + `md/` docs + video
- **[readmenator-diagrams/](./readmenator-diagrams/)** -- Component diagrams.
  - `analysis.json` + `graph LR` markdown + per-component pages + `index.html`
- **[readmenator-rules/](./readmenator-rules/)** -- Suggested Semgrep rules (`*.yml`),
  `yara_rules.yar` (YARA-lite) + `exclusions.yaml` (false-positive blocklist)
- **[readmenator.mp4](./readmenator.mp4)** -- Cinematic synthwave overview video
- **[.cursorrules](./.cursorrules)** -- Generated AI assistant rules
- **[readmenator_audit.sarif](./readmenator_audit.sarif)** -- SARIF v2.1.0 audit (when security scan is on)

Cache (`.readmenator_cache/`), packaged agent skills (`.claude/skills/`), and the
GitHub wiki mirror are also produced on `run`/`--rebuild`.

AI agents: Read `readmenator-wiki/index.md` first for the big picture, then `readmenator-agent/INDEX.md` for grep-friendly lookup.
Developers: Read `KNOWLEDGE_BASE.md` for full architecture reference, open `readmenator-maps/index.html` for the visual gallery.
<!-- /readmenator-kb-link -->

<!-- deploynator-footer -->

---

Deployed with [deploynator](https://github.com/grisuno/deploynator)

<!-- /deploynator-footer -->
