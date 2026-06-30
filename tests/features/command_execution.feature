@security
Feature: Ejecución segura de comandos (SEC-002)
  Para evitar inyección de código, la API solo debe invocar acciones
  pre-registradas con parámetros validados, nunca construir shells dinámicos.

  Background:
    Given una app Flask configurada para tests
    And un usuario autenticado con un token JWT válido

  Scenario: No hay subprocess dinámico en el código
    When escaneo el repositorio en busca de subprocess con código dinámico
    Then no debe haber llamadas a "subprocess.run(['python3', '-c', ...])"
    And no debe haber llamadas a "os.system(f'python -c ...')"
    And no debe haber usos de "eval(" o "exec(" sobre input del usuario

  Scenario: Comando no permitido es rechazado
    When el usuario invoca la acción "do_evil_rm_rf" con params {"path": "/"}
    Then debe recibir HTTP 403
    And el cuerpo debe contener "no permitida"

  Scenario: Comando sin token JWT es rechazado
    Given que el usuario NO está autenticado
    When invoca la acción "do_net_scan" con params {}
    Then debe recibir HTTP 401

  Scenario: Comando con parámetros inválidos es rechazado
    When el usuario invoca la acción "do_resp_kill_proc" con params {"pid": "no-es-numero"}
    Then debe recibir HTTP 400
    And el cuerpo debe mencionar el parámetro "pid"

  Scenario: Comando con parámetros faltantes es rechazado
    When el usuario invoca la acción "do_resp_block_ip" con params {}
    Then debe recibir HTTP 400
    And el cuerpo debe mencionar "ip_address"

  Scenario: Comando válido se ejecuta vía llamada Python
    When el usuario invoca la acción "do_net_scan" con params {}
    Then debe recibir HTTP 200
    And el cuerpo debe contener "output" con el resultado del handler
    And debe existir un registro de auditoría con action="do_net_scan" y result="ok"

  Scenario: Comando que falla genera registro de auditoría de error
    Given la acción "do_resp_kill_proc" con pid inválido en su handler
    When el usuario invoca la acción "do_resp_kill_proc" con params {"pid": -1}
    Then debe recibir HTTP 500
    And debe existir un registro de auditoría con action="do_resp_kill_proc" y result="error"

  Scenario: Los registros de auditoría son consultables
    When el usuario consulta GET /api/audit
    Then debe recibir HTTP 200
    And la respuesta debe incluir los últimos 100 registros
