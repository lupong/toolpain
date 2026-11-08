"""Allowlisted codegen sidecar services."""

from __future__ import annotations

import pytest

from runner.services import ServiceGuardError, validate_services


def test_validate_postgres_service() -> None:
    specs = validate_services(
        [
            {
                "name": "postgres",
                "image": "postgres:16-alpine",
                "env": {
                    "POSTGRES_PASSWORD": "toolpain",
                    "POSTGRES_USER": "toolpain",
                    "POSTGRES_DB": "toolbox",
                },
                "port": 5432,
            }
        ]
    )
    assert len(specs) == 1
    assert specs[0].name == "postgres"
    assert specs[0].image == "postgres:16-alpine"


def test_reject_fixture_as_service_name() -> None:
    with pytest.raises(ServiceGuardError, match="reserved|invalid"):
        validate_services([{"name": "fixture", "image": "postgres:16-alpine"}])


def test_reject_arbitrary_image() -> None:
    with pytest.raises(ServiceGuardError, match="allowlisted"):
        validate_services([{"name": "evil", "image": "evil/pwn:latest"}])


def test_empty_services_ok() -> None:
    assert validate_services([]) == []
    assert validate_services(None) == []
