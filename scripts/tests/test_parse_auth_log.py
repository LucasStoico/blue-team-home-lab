"""
Testes do parse_auth_log.

Rodar:
    pip install -r ../requirements.txt
    pytest -v
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parse_auth_log import parse_line, iter_events, summarize  # noqa: E402


def test_failed_password_invalid_user():
    line = "Mar 15 08:23:41 victim sshd[2394]: Failed password for invalid user admin from 203.0.113.55 port 41232 ssh2"
    ev = parse_line(line, year=2024)
    assert ev is not None
    assert ev["event"]["action"] == "ssh_login_failed"
    assert ev["event"]["outcome"] == "failure"
    assert ev["user"]["name"] == "admin"
    assert ev["source"]["ip"] == "203.0.113.55"
    assert ev["source"]["port"] == 41232
    assert ev["@timestamp"] == "2024-03-15T08:23:41Z"


def test_accepted_password():
    line = "Mar 15 08:30:02 victim sshd[2410]: Accepted password for labuser from 192.168.56.10 port 52012 ssh2"
    ev = parse_line(line, year=2024)
    assert ev is not None
    assert ev["event"]["action"] == "ssh_login_success"
    assert ev["event"]["outcome"] == "success"
    assert ev["user"]["name"] == "labuser"
    assert ev["source"]["ip"] == "192.168.56.10"


def test_accepted_publickey():
    line = "Mar 15 09:00:00 victim sshd[2500]: Accepted publickey for lucas from 192.168.56.10 port 52999 ssh2"
    ev = parse_line(line, year=2024)
    assert ev is not None
    assert ev["event"]["outcome"] == "success"


def test_invalid_user():
    line = "Mar 15 08:23:40 victim sshd[2394]: Invalid user oracle from 203.0.113.55"
    ev = parse_line(line, year=2024)
    assert ev is not None
    assert ev["event"]["action"] == "ssh_invalid_user"
    assert ev["user"]["name"] == "oracle"


def test_non_ssh_line_ignored():
    line = "Mar 15 08:23:41 victim sudo[3001]: pam_unix(sudo:session): session opened for user root"
    assert parse_line(line, year=2024) is None


def test_garbage_line_ignored():
    assert parse_line("isto nao e um log valido", year=2024) is None
    assert parse_line("", year=2024) is None


def test_summary_flags_brute_force():
    lines = []
    # 12 falhas do mesmo IP -> deve ser marcado como suspeito (limiar 10)
    for i in range(12):
        lines.append(
            f"Mar 15 08:2{i%10}:41 victim sshd[2394]: "
            f"Failed password for invalid user admin from 203.0.113.55 port 4123{i} ssh2"
        )
    # 1 sucesso depois das falhas -> dica de credential stuffing bem-sucedido
    lines.append(
        "Mar 15 08:31:00 victim sshd[2500]: "
        "Accepted password for admin from 203.0.113.55 port 51000 ssh2"
    )
    events = list(iter_events(lines, year=2024))
    report = summarize(events, threshold=10)
    suspect = report["suspects"][0]
    assert suspect["source_ip"] == "203.0.113.55"
    assert suspect["failed_attempts"] == 12
    assert suspect["brute_force_suspect"] is True
    assert suspect["credential_stuffing_hint"] is True


def test_summary_below_threshold_not_flagged():
    lines = [
        "Mar 15 08:20:41 victim sshd[2394]: Failed password for labuser from 198.51.100.9 port 41232 ssh2",
        "Mar 15 08:20:45 victim sshd[2394]: Failed password for labuser from 198.51.100.9 port 41233 ssh2",
    ]
    events = list(iter_events(lines, year=2024))
    report = summarize(events, threshold=10)
    assert report["suspects"][0]["brute_force_suspect"] is False
