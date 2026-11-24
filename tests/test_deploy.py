import configparser
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from passd.gateway import DEFAULT_ALLOWED_CIDRS

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"


def test_deploy_units(tmp_path):
    def read_unit(name):
        # systemd allows repeated keys (e.g. allow + deny SystemCallFilter lines); configparser must too.
        config = configparser.ConfigParser(interpolation=None, strict=False)
        assert config.read(DEPLOY / name)
        service = config["Service"]
        for key in ("NoNewPrivileges", "ProtectHome", "PrivateTmp", "MemoryDenyWriteExecute",
                    "PrivateDevices", "ProtectKernelTunables", "ProtectKernelModules", "ProtectControlGroups",
                    "RestrictNamespaces", "RestrictSUIDSGID", "LockPersonality"):
            assert service[key] == "yes"
        assert service["CapabilityBoundingSet"] == ""
        raw = (DEPLOY / name).read_text()
        assert "SystemCallFilter=@system-service" in raw and "SystemCallFilter=~@privileged @resources" in raw
        assert service["ProtectSystem"] == "strict"
        assert set(service["RestrictAddressFamilies"].split()) == {"AF_UNIX", "AF_INET", "AF_INET6"}
        assert service["ExecStart"].startswith("/opt/passd/bin/passd ")
        return config

    broker = read_unit("passd.service")["Service"]
    assert broker["User"] == "passd"
    assert broker["Group"] == "passd-admin"
    assert broker["StandardInput"] == "file:/run/passd-unlock/input"
    assert set(broker["ReadWritePaths"].split()) == {"/var/lib/passd", "/run/passd"}
    assert "--master-password-stdin --group-socket" in broker["ExecStart"]
    gateway = read_unit("passd-gateway.service")
    assert gateway["Unit"]["BindsTo"] == "passd.service"
    assert gateway["Service"]["DynamicUser"] == "yes"
    assert gateway["Service"]["SupplementaryGroups"] == "passd-admin"
    command = gateway["Service"]["ExecStart"]
    assert "--listen ${PASSD_GATEWAY_LISTEN}" in command
    assert re.findall(r"--allow-cidr (\S+)", command) == list(DEFAULT_ALLOWED_CIDRS[:2])
    runtime = [line.split() for line in (DEPLOY / "passd.conf").read_text().splitlines()]
    assert ["d", "/run/passd", "0750", "passd", "passd-admin", "-"] in runtime
    assert ["d", "/run/passd-unlock", "0700", "root", "root", "-"] in runtime
    assert ["p", "/run/passd-unlock/input", "0600", "root", "root", "-"] in runtime

    if analyzer := shutil.which("systemd-analyze"):
        paths = []
        for unit in sorted(DEPLOY.glob("*.service")):
            path = tmp_path / unit.name
            # The production executable is installed by the Linux deploy script.
            path.write_text(unit.read_text().replace("ExecStart=/opt/passd/bin/passd ",
                                                     "ExecStart=/bin/true "))
            paths.append(str(path))
        subprocess.run([analyzer, "verify", "--man=no", *paths],
                       check=True, capture_output=True, text=True, timeout=30)


def test_readiness_driver_runs_against_disposable_daemon():
    result = subprocess.run(
        [str(DEPLOY / "e2e-readiness.sh")],
        env={**os.environ, "PASSD_PYTHON": sys.executable},
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count("PASS ") == 12
    assert "FAIL " not in result.stdout + result.stderr
