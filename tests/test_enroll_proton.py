import json
import os
import shutil
import sys
import threading
from pathlib import Path

import pytest

from passd import cli
from passd.config import Config
from passd.server import PassdUnixServer
from passd.service import PassdService

MASTER = "enrollment-test-master"
CANARY = "pst_" + "enrollment-canary" + "::" + "private-key"
URL = "https://account.proton.me/desktop/login?app=pass#payload=test\n"
CREATE = ["agent", "create", "passd-test", "--expiration", "1w", "--vault", "agents"]
DELETE = ["agent", "delete", "passd-test"]


@pytest.fixture
def enrollment(tmp_path, monkeypatch, capsys, caplog):
    fake = tmp_path / "pass-cli"
    shutil.copy2(Path(__file__).parent / "fixtures/enroll-pass-cli", fake)
    owner_tmp = tmp_path / "owner"
    owner_tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(owner_tmp))
    monkeypatch.setattr("tempfile.tempdir", str(owner_tmp))
    monkeypatch.setenv("PATH", os.pathsep.join((str(tmp_path), str(Path(sys.executable).parent), os.defpath)))
    monkeypatch.setenv("PASSD_MASTER_PASSWORD", MASTER)
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "ambient-token")
    monkeypatch.delenv("PASSD_REMOTE", raising=False)
    cfg = Config.initialize(tmp_path / "data", MASTER)
    cfg.proton_agent_binary = str(fake)
    cfg.proton_agent_name = "passd-test"
    service = PassdService(cfg, cfg.derive_and_verify(MASTER))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PASSD_SOCKET", "broker.sock")
    server = PassdUnixServer(cfg.socket_path, service)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()

    def run(mode):
        (tmp_path / "mode").write_text(mode)
        result = cli.main(["--data-dir", str(cfg.data_dir), "enroll", "proton"])
        output = capsys.readouterr()
        calls = [
            json.loads(line) for line in (tmp_path / "calls").read_text().splitlines()
        ]
        assert CANARY not in output.out + output.err + caplog.text
        assert all(CANARY.encode() not in path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())
        owner_calls = [args for args, session, _ in calls if Path(session).parent == owner_tmp]
        assert owner_calls[-1] == ["logout", "--force"]
        assert list(owner_tmp.iterdir()) == []
        return result, output, calls, owner_calls

    try:
        yield service, run
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
        service.close()


def test_entitlement_refusal(enrollment):
    service, run = enrollment
    result, output, _, owner_calls = run("refused")
    assert result != 0
    assert "entitlement" in output.err and "Proton" in output.err
    assert owner_calls == [["login"], ["logout", "--force"]]
    assert not service.proton_agent.status(check_session=False)["pat_set"]


@pytest.mark.parametrize("mode", ["success", "missing"])
def test_entitled_session_and_no_token_leak(enrollment, mode):
    service, run = enrollment
    result, output, calls, owner_calls = run(mode)
    assert result == 0
    assert output.out == URL and output.err == ""
    assert owner_calls.count(CREATE) == 1
    assert (["vault", "create", "--name", "agents"] in owner_calls) == (mode == "missing")
    assert owner_calls[-2][:3] == ["pat", "access", "list-access"]
    owner_logout = calls.index(next(entry for entry in calls if entry[0] == ["logout", "--force"] and entry[1] == calls[0][1]))
    assert [args for args, _, pat in calls[owner_logout + 1:] if pat] == [["login"]]
    assert service.proton_agent.status()["session_ok"] is True


@pytest.mark.parametrize("mode", ["extra", "malformed", "wrong-share", "bad-token", "handoff"])
def test_partial_failure_revokes_and_disables(enrollment, monkeypatch, mode):
    service, run = enrollment
    if mode == "handoff":
        def fail(_pat):
            raise RuntimeError(CANARY)
        monkeypatch.setattr(service, "set_proton_agent_pat", fail)
    result, _, _, owner_calls = run(mode)
    assert result != 0
    assert owner_calls[-2] == DELETE
    assert service.proton_agent.status()["disabled"] is True
    assert not service.proton_agent.session_dir.exists()


def test_broker_login_failure_disables(enrollment):
    service, run = enrollment
    result, output, _, _ = run("login-fail")
    assert result != 0
    assert "Revoke" in output.err
    assert service.proton_agent.status()["disabled"] is True
    assert not service.proton_agent.session_dir.exists()


@pytest.mark.parametrize("mode", ["duplicate", "existing"])
def test_ambiguous_vault_or_existing_identity_stops_before_token(enrollment, mode):
    _, run = enrollment
    result, _, _, owner_calls = run(mode)
    assert result != 0
    assert CREATE not in owner_calls and DELETE not in owner_calls


def test_keyboard_interrupt_revokes_and_wipes(enrollment, monkeypatch):
    service, run = enrollment
    stock_runner = cli.StockProtonRunner()

    def interrupted(args, env, **kwargs):
        if args[:3] == ("pat", "access", "list-access"):
            raise KeyboardInterrupt
        return stock_runner(args, env, **kwargs)

    monkeypatch.setattr(cli, "StockProtonRunner", lambda: interrupted)
    result, output, _, owner_calls = run("success")
    assert result == 130
    assert "interrupted" in output.err
    assert owner_calls[-2] == DELETE
    assert service.proton_agent.status()["disabled"] is True
