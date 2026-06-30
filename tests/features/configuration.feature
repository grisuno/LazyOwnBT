@config
Feature: Configuración y dependencias (CFG-001, CFG-002)

  Background:
    Given un entorno limpio sin variables LBT ni JWT_SECRET_KEY
    And un hash bcrypt válido en ADMIN_PASSWORD_HASH

  Scenario: Las variables de entorno se cargan
    Given JWT_SECRET_KEY con 64 caracteres
    And FLASK_ENV=development
    When cargo la configuración
    Then jwt_secret_key debe coincidir con el valor provisto

  Scenario: Falta una variable obligatoria y la app falla ruidosamente
    Given FLASK_ENV=production
    And JWT_SECRET_KEY no está definida
    When cargo la configuración
    Then debe lanzar ConfigError

  Scenario: requirements.txt contiene todas las dependencias que importa el código
    Given el árbol de código fuente bajo lazyownbt
    When extraigo los imports top-level
    Then cada paquete importado debe figurar en pyproject.toml (deps o extras)
    And no debe haber paquetes listados en requirements.txt que el código no use
