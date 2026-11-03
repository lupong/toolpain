"""M4: strace parser, noise filter, decoy set."""

from __future__ import annotations

from pathlib import Path

from sandbox.decoys import plant_decoys
from sandbox.trace import is_noise_path, parse_line, parse_strace_file, parse_strace_text

SAMPLE = Path(__file__).parent / "fixtures" / "sample_strace.txt"


def test_parse_sample_file() -> None:
    events = parse_strace_file(SAMPLE)
    decoy = [e for e in events if e.path == "/workspace/canaries/decoy_secret.txt"]
    assert len(decoy) == 1
    assert decoy[0].kind == "file" and decoy[0].ok and decoy[0].pid == 1200
    assert decoy[0].flags == "O_RDONLY|O_CLOEXEC" and not decoy[0].is_write

    missing = next(e for e in events if e.path == "/workspace/missing.txt")
    assert missing.pid == 1201 and missing.error == "ENOENT" and not missing.ok

    connects = [e for e in events if e.syscall == "connect"]
    assert [(c.addr, c.port, c.ok) for c in connects[:4]] == [
        ("10.66.42.53", 443, True),
        ("93.184.216.34", 443, False),
        ("2606:2800::1", 80, False),
        ("/var/run/nscd/socket", None, False),
    ]
    assert connects[1].error == "ENETUNREACH"
    assert any(c.addr == "169.254.169.254" for c in connects)  # <unfinished ...> line kept

    sh = next(e for e in events if e.syscall == "execve" and e.path == "/bin/sh")
    assert sh.kind == "proc" and sh.argv == ["sh", "-c", "id"]
    assert next(e for e in events if e.syscall == "bind").port == 8080
    assert next(e for e in events if e.path == "/tmp/out.txt").is_write


def test_parser_ignores_noise_and_resumed() -> None:
    assert parse_line("1 1.5 <... connect resumed>) = 0") is None
    assert parse_line("1 1.5 mmap(NULL, 4096, PROT_READ) = 0x7f") is None
    assert parse_line("garbage") is None


def test_wallclock_timestamps_with_base_date() -> None:
    events = parse_strace_text('1 00:00:01.500000 openat(AT_FDCWD, "/x", O_RDONLY) = 3', 1000.0)
    assert events[0].ts == 1001.5


def test_noise_paths() -> None:
    assert is_noise_path("/usr/lib/python3.12/os.py")
    assert is_noise_path("/usr/local/lib/python3.12/site-packages/x/y.py")
    assert is_noise_path(None)
    assert not is_noise_path("/workspace/canaries/decoy_secret.txt")
    assert not is_noise_path("/tmp/out.txt")


def test_plant_decoys(tmp_path: Path) -> None:
    d = plant_decoys(tmp_path, "s_abc")
    assert (
        (tmp_path / "canaries" / "decoy_secret.txt").read_text().startswith("decoy-secret-s_abc-")
    )
    assert (tmp_path / ".env").read_text() == "API_TOKEN=decoy-s_abc\n"
    assert d.is_decoy_path("/workspace/canaries/decoy_secret.txt")
    assert d.is_decoy_path("/workspace/.env")
    assert not d.is_decoy_path("/workspace/other.txt")
    other = plant_decoys(tmp_path / "b", "s_abc")
    assert other.secret_value != d.secret_value  # per-scan nonce
