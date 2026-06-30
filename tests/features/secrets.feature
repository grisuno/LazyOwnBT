@security
Feature: Manejo seguro de secretos (SEC-001)
  Para evitar fugas de credenciales, la aplicación debe obtener todos
  sus secretos desde el entorno y nunca incluirlos en el código fuente.

  Background:
    Given un entorno limpio sin variables LBT ni JWT_SECRET_KEY

  Scenario: No hay secretos hardcodeados en el código
    When escaneo el repositorio en busca de strings sospechosos
    Then no debe aparecer la cadena literal "your-secret-key"
    And no debe aparecer la comparación "username == 'admin' and password == 'password'"

  Scenario: La app aborta en producción si falta JWT_SECRET_KEY
    Given FLASK_ENV=production
    And JWT_SECRET_KEY no está definida
    When intento crear la aplicación
    Then debe lanzar ConfigError con el código SEC-001.2

  Scenario: La app genera un secreto efímero en development
    Given FLASK_ENV=development
    And JWT_SECRET_KEY no está definida
    When se carga la configuración
    Then debe generar un secreto aleatorio de al menos 32 bytes
    And debe imprimir una advertencia en stderr

  Scenario: La app rechaza secretos cortos
    Given FLASK_ENV=production
    And JWT_SECRET_KEY="short"
    When intento crear la aplicación
    Then debe lanzar ConfigError con el código SEC-001.3

  Scenario: La contraseña admin se valida contra un hash bcrypt
    Given una app Flask configurada para tests
    And un hash bcrypt válido en ADMIN_PASSWORD_HASH
    When el usuario intenta hacer login con la contraseña correcta
    Then debe recibir un access_token
    When el usuario intenta hacer login con la contraseña incorrecta
    Then debe recibir HTTP 401

  Scenario: El archivo .env está fuera del repositorio
    Then el archivo ".gitignore" debe contener la línea ".env"
    And debe existir un ".env.example" versionado

  Scenario: El logger redacta secretos en sus mensajes
    Given un logger con SecretsFilter instalado
    When registro el mensaje "JWT_SECRET_KEY=abc123 DEBUG=1"
    Then el mensaje almacenado debe contener "[REDACTED]"
    And no debe contener "abc123"
