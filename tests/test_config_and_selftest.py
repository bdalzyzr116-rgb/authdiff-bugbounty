from __future__ import annotations

import json
import os

from authdiff.config import Config
from authdiff.selftest import run_selftest


def test_selftest_passes() -> None:
    assert run_selftest() == 0


def test_config_env_interpolation(tmp_path) -> None:
    os.environ["ADF_TEST_TOKEN"] = "secret-xyz"
    cfg_obj = {
        "scope": {"allow_hosts": ["api.x.com"]},
        "identities": [
            {"id": "alice", "headers": {"Authorization": "Bearer ${ADF_TEST_TOKEN}"}},
            {"id": "bob", "headers": {"Authorization": "Bearer B"}},
        ],
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg_obj), encoding="utf-8")
    cfg = Config.load(str(p))
    assert cfg.identities["alice"].headers["Authorization"] == "Bearer secret-xyz"


def test_config_requires_two_identities(tmp_path) -> None:
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"scope": {"allow_hosts": ["x"]},
                             "identities": [{"id": "solo"}]}), encoding="utf-8")
    try:
        Config.load(str(p))
        assert False, "should have raised"
    except ValueError:
        pass
