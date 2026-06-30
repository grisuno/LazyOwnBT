@security
Feature: Modo producción del servidor web (SEC-003)
  Para evitar exposición accidental, el servidor debe correr con
  configuración segura por defecto y solo permitir overrides explícitos.

  Background:
    Given un entorno limpio sin variables LBT ni JWT_SECRET_KEY
    And JWT_SECRET_KEY con 64 caracteres
    And ADMIN_PASSWORD con 32 caracteres

  Scenario: El modo debug está desactivado por defecto
    Given FLASK_ENV=production
    When se crea la app
    Then debug debe ser False

  Scenario: --debug solo es válido en development
    Given FLASK_ENV=production
    When se invoca la CLI con --debug
    Then debe abortar con un error que mencione SEC-003.1

  Scenario: El bind por defecto es loopback
    Given no se especifica LAZYOWN_BIND
    When se carga la configuración
    Then el host debe ser "127.0.0.1"

  Scenario: Bind público genera warning
    Given LAZYOWN_BIND="0.0.0.0"
    When se crea la app
    Then debe aparecer un warning mencionando SEC-003.2

  Scenario: Talisman fuerza HTTPS en producción
    Given FLASK_ENV=production
    When se crea la app
    Then Talisman debe estar configurado con force_https=True

  Scenario: Talisman NO fuerza HTTPS en development
    Given FLASK_ENV=development
    When se crea la app
    Then Talisman debe estar configurado con force_https=False

  Scenario: La CSP no contiene hashes hardcodeados
    When se obtiene la configuración CSP
    Then la CSP no debe incluir hashes sha256
