# LazyOwnBT

![image](https://github.com/user-attachments/assets/45898b81-52fd-4785-afe3-bd1bdfa51fec)


LazyOwnBT es una herramienta de seguridad defensiva (Blue Team) diseñada para la detección de amenazas, análisis de logs, monitoreo de procesos y redes, verificación de integridad de archivos, endurecimiento del sistema, generación de informes y respuesta a incidentes en entornos Linux.

Esta herramienta está pensada para ser utilizada por equipos de seguridad, analistas de SOC y profesionales de ciberseguridad que buscan automatizar tareas de monitoreo y protección en sistemas operativos basados en Linux.

📌 Características Principales
Detección de Amenazas : Análisis avanzado de logs (/var/log/auth.log, /var/log/syslog, etc.) para detectar intentos de inicio de sesión fallidos, uso sospechoso de sudo, usuarios creados o eliminados.
Monitoreo de Procesos y Redes : Detección de procesos y conexiones sospechosas basadas en nombres comunes de malware, puertos peligrosos o comportamiento inusual.
Verificación de Integridad de Archivos (FIM) : Comparación de hashes de archivos críticos para identificar modificaciones no autorizadas.
Endurecimiento del Sistema (Hardening) : Auditoría de configuraciones seguras para servicios como SSH, firewall (ufw), kernel y más.
Respuesta a Incidentes : Bloqueo de IPs maliciosas, terminación de procesos sospechosos y escaneo de memoria en busca de cadenas peligrosas.
Generación de Informes : Resúmenes estructurados de alertas, hallazgos y recomendaciones de mitigación.
Módulos Modularizados : Arquitectura limpia con componentes reutilizables y fácil de extender.
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
