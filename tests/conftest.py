"""Construye un repositorio git real y temporal con una historia conocida,
para probar el escáner sin depender de ningún repositorio externo."""
from __future__ import annotations

import git
import pytest

AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
GENERIC_SECRET = "x7K9mQ2pL5vN8wR3tY6uI1oP4aS0dF7g"


@pytest.fixture
def demo_repo(tmp_path):
    path = str(tmp_path / "demo")
    repo = git.Repo.init(path, initial_branch="main")
    repo.config_writer().set_value("user", "name", "Tester").release()
    repo.config_writer().set_value("user", "email", "tester@example.com").release()

    def write(name: str, content: str):
        (tmp_path / "demo" / name).write_text(content, encoding="utf-8")

    # 1) commit inicial, inocuo
    write("README.md", "# Proyecto demo\n")
    repo.index.add(["README.md"])
    repo.index.commit("inicial")

    # 2) agrega una clave de AWS por error
    write("config.py", f'AWS_KEY = "{AWS_KEY}"\n')
    repo.index.add(["config.py"])
    repo.index.commit("agrega configuracion")

    # 3) se da cuenta y la quita (pero sigue en el historial)
    write("config.py", 'AWS_KEY = os.environ["AWS_KEY"]\n')
    repo.index.add(["config.py"])
    repo.index.commit("saca la clave hardcodeada")

    # 4) agrega un secreto genérico (alta entropía) y un placeholder que NO debe marcarse
    write("settings.py",
          f'api_key = "{GENERIC_SECRET}"\n'
          f'api_key_default = "changeme"\n')
    repo.index.add(["settings.py"])
    repo.index.commit("agrega settings")

    return path
