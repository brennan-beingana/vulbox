"""Run-scoping: a provider sees only their own runs; an admin sees every run;
a foreign run reads as 404 (not 403, to avoid id enumeration). Exercised at the
service level so no Docker/orchestrator is needed — consistent with the rest of
the unit suite.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.core.security import ROLE_ADMIN, ROLE_PROVIDER
from app.models.run import AssessmentRun
from app.services.run_service import RunService


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False)()
    # Two providers' runs interleaved.
    for owner, name in [
        ("alice@vulbox.local", "alice-1"),
        ("bob@vulbox.local", "bob-1"),
        ("alice@vulbox.local", "alice-2"),
    ]:
        session.add(AssessmentRun(project_name=name, submitted_by=owner, status="SUBMITTED"))
    session.commit()
    yield session
    session.close()


def _user(email, role=ROLE_PROVIDER):
    return SimpleNamespace(email=email, role=role)


def test_provider_lists_only_own_runs(db):
    runs = RunService.list_runs(db, _user("alice@vulbox.local"))
    assert {r.project_name for r in runs} == {"alice-1", "alice-2"}


def test_admin_lists_all_runs(db):
    runs = RunService.list_runs(db, _user("admin@vulbox.local", ROLE_ADMIN))
    assert len(runs) == 3


def test_internal_caller_sees_all_runs(db):
    # user=None is the unauthenticated internal path (e.g. orchestrator).
    assert len(RunService.list_runs(db, None)) == 3


def test_authorize_allows_owner(db):
    run = RunService.list_runs(db, None)[0]  # most recent: alice-2
    assert RunService.authorize(run, _user(run.submitted_by)) is run


def test_authorize_allows_admin(db):
    bob_run = next(r for r in RunService.list_runs(db, None) if r.submitted_by == "bob@vulbox.local")
    assert RunService.authorize(bob_run, _user("admin@vulbox.local", ROLE_ADMIN)) is bob_run


def test_authorize_blocks_foreign_run_as_404(db):
    bob_run = next(r for r in RunService.list_runs(db, None) if r.submitted_by == "bob@vulbox.local")
    with pytest.raises(HTTPException) as exc:
        RunService.authorize(bob_run, _user("alice@vulbox.local"))
    assert exc.value.status_code == 404


def test_unauthenticated_request_is_rejected():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        assert client.get("/runs").status_code == 401
        assert client.get("/reports/1").status_code == 401
