from __future__ import annotations

from scripts.bump_version import bump_version


def test_bump_version_updates_citation_version_and_date(tmp_path, monkeypatch) -> None:
    files = {
        "pyproject.toml": 'version = "0.5.0"\n',
        "actionscope/__init__.py": 'version = "0.5.0"\n',
        "action.yml": "default: '0.5.0'\n",
        "CITATION.cff": "version: 0.5.0\ndate-released: 2026-08-10\n",
    }
    for filename, content in files.items():
        path = tmp_path / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    bump_version("0.5.0", "0.6.0", release_date="2026-12-01")

    citation = (tmp_path / "CITATION.cff").read_text(encoding="utf-8")
    assert "version: 0.6.0" in citation
    assert "date-released: 2026-12-01" in citation
    for filename in ("pyproject.toml", "actionscope/__init__.py", "action.yml"):
        assert "0.6.0" in (tmp_path / filename).read_text(encoding="utf-8")
