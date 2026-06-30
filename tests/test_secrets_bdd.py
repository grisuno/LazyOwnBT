"""BDD runner para `secrets.feature`.

pytest-bdd convierte cada Scenario en un test individual. Los steps se
descubren automáticamente desde `tests/steps/conftest.py`.
"""

from __future__ import annotations

from pytest_bdd import scenarios

scenarios("secrets.feature")
