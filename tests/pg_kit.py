"""A real, throwaway PostgreSQL cluster for the replay-store tests. No mocks.

Skips when no server binaries exist or psycopg is missing, unless ZTS_REQUIRE_POSTGRES=1
(CI), where either is a failure.
"""

from __future__ import annotations

import glob
import os
import shutil
import socket
import subprocess
import tempfile
import time

import pytest

REQUIRED = os.environ.get("ZTS_REQUIRE_POSTGRES") == "1"


def _skip(reason: str):
    if REQUIRED:
        raise RuntimeError(f"ZTS_REQUIRE_POSTGRES=1 but {reason}")
    pytest.skip(reason, allow_module_level=True)


try:
    import psycopg  # noqa: F401
except ImportError:
    _skip("psycopg is not installed")


def _bin() -> str:
    for pattern in ("/usr/lib/postgresql/*/bin", "/usr/pgsql-*/bin", "/opt/homebrew/opt/postgresql*/bin"):
        found = sorted(glob.glob(pattern))
        if found and os.path.exists(os.path.join(found[-1], "initdb")):
            return found[-1]
    found = shutil.which("initdb")
    if found:
        return os.path.dirname(found)
    _skip("no PostgreSQL server binaries (initdb) found")
    return ""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Cluster:
    def __init__(self) -> None:
        self.bin = _bin()
        self.dir = tempfile.mkdtemp(prefix="zts-pg-")
        self.port = _free_port()
        self.prefix: list[str] = []
        if os.geteuid() == 0:  # PostgreSQL refuses to run as root
            shutil.chown(self.dir, user="postgres")
            self.prefix = ["runuser", "-u", "postgres", "--"]
        self._run("initdb", "-D", f"{self.dir}/data", "-A", "trust", "-U", "zts")
        self._run("pg_ctl", "-D", f"{self.dir}/data", "-o",
                  f"-p {self.port} -k {self.dir} -c listen_addresses=127.0.0.1", "-l", f"{self.dir}/log", "-w", "start")

    def _run(self, tool: str, *args: str) -> None:
        subprocess.run([*self.prefix, os.path.join(self.bin, tool), *args], check=True,
                       capture_output=True, timeout=120)

    @property
    def dsn(self) -> str:
        return f"host=127.0.0.1 port={self.port} user=zts dbname=postgres"

    def stop(self) -> None:
        try:
            self._run("pg_ctl", "-D", f"{self.dir}/data", "-m", "immediate", "stop")
        finally:
            shutil.rmtree(self.dir, ignore_errors=True)

    def terminate_backends(self) -> None:
        with psycopg.connect(self.dsn, autocommit=True) as c:
            c.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                      "WHERE pid <> pg_backend_pid() AND datname = 'postgres'")
            time.sleep(0.05)


@pytest.fixture(scope="session")
def cluster():
    c = Cluster()
    yield c
    c.stop()
