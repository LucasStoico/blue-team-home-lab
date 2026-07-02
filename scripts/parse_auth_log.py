#!/usr/bin/env python3
"""
parse_auth_log.py
-----------------
Parseia e normaliza logs de autenticação do Linux (/var/log/auth.log) em
eventos JSON estruturados no padrão ECS (Elastic Common Schema), prontos
para ingestão no Elasticsearch.

Também agrega tentativas de login por IP de origem para sinalizar
candidatos a brute-force (T1110.001) antes mesmo do SIEM.

Uso:
    # Emite um evento JSON por linha (JSONL), pronto para o Filebeat/ES
    python parse_auth_log.py /var/log/auth.log

    # Modo agregação: resumo de tentativas falhas por IP de origem
    python parse_auth_log.py /var/log/auth.log --summary --threshold 10

    # Lendo da entrada padrão
    cat auth.log | python parse_auth_log.py -

Autor: Lucas Stoico Quirino
Licença: MIT
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Padrões de parsing
# ---------------------------------------------------------------------------

# Cabeçalho syslog: "Mar 15 08:23:41 victim sshd[2394]: <mensagem>"
SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[\w\-/]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<src_port>\d+)"
)

ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<src_port>\d+)"
)

INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_syslog_ts(ts: str, year: int) -> str:
    """Converte 'Mar 15 08:23:41' em timestamp ISO 8601 UTC."""
    parts = ts.split()
    month = _MONTHS.get(parts[0], 1)
    day = int(parts[1])
    hh, mm, ss = (int(x) for x in parts[2].split(":"))
    dt = datetime(year, month, day, hh, mm, ss, tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def parse_line(line: str, year: int | None = None) -> dict | None:
    """
    Parseia uma linha do auth.log em um evento ECS.
    Retorna None quando a linha não é um evento SSH relevante.
    """
    if year is None:
        year = datetime.now(timezone.utc).year

    head = SYSLOG_RE.match(line.strip())
    if not head:
        return None

    program = head.group("program")
    if program != "sshd":
        return None

    message = head.group("message")
    ts_iso = _parse_syslog_ts(head.group("ts"), year)

    base = {
        "@timestamp": ts_iso,
        "host": {"name": head.group("host")},
        "process": {"name": "sshd", "pid": int(head.group("pid") or 0)},
        "event": {"category": ["authentication"], "module": "ssh"},
        "log": {"original": line.strip()},
    }

    m = FAILED_RE.search(message)
    if m:
        base["event"].update({"action": "ssh_login_failed", "outcome": "failure"})
        base["user"] = {"name": m.group("user")}
        base["source"] = {"ip": m.group("src_ip"), "port": int(m.group("src_port"))}
        return base

    m = ACCEPTED_RE.search(message)
    if m:
        base["event"].update({"action": "ssh_login_success", "outcome": "success"})
        base["user"] = {"name": m.group("user")}
        base["source"] = {"ip": m.group("src_ip"), "port": int(m.group("src_port"))}
        return base

    m = INVALID_USER_RE.search(message)
    if m:
        base["event"].update({"action": "ssh_invalid_user", "outcome": "failure"})
        base["user"] = {"name": m.group("user")}
        base["source"] = {"ip": m.group("src_ip")}
        return base

    return None


def iter_events(lines, year=None):
    """Gera eventos ECS a partir de um iterável de linhas."""
    for line in lines:
        event = parse_line(line, year=year)
        if event is not None:
            yield event


def summarize(events, threshold: int = 10) -> dict:
    """
    Agrega falhas por IP de origem. IPs acima do limiar são marcados
    como candidatos a brute-force (MITRE ATT&CK T1110.001).
    """
    fails = defaultdict(int)
    users = defaultdict(set)
    successes = defaultdict(int)

    for ev in events:
        outcome = ev["event"].get("outcome")
        src = ev.get("source", {}).get("ip")
        if not src:
            continue
        if outcome == "failure":
            fails[src] += 1
            if "user" in ev:
                users[src].add(ev["user"]["name"])
        elif outcome == "success":
            successes[src] += 1

    report = []
    for ip, count in sorted(fails.items(), key=lambda kv: kv[1], reverse=True):
        report.append({
            "source_ip": ip,
            "failed_attempts": count,
            "distinct_users": sorted(users[ip]),
            "successful_logins": successes.get(ip, 0),
            "brute_force_suspect": count >= threshold,
            "credential_stuffing_hint": count >= threshold and successes.get(ip, 0) > 0,
        })
    return {"threshold": threshold, "suspects": report}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Parseia auth.log SSH para JSON/ECS.")
    ap.add_argument("path", help="Arquivo de auth.log (use '-' para stdin).")
    ap.add_argument("--summary", action="store_true",
                    help="Emite resumo agregado por IP em vez de eventos.")
    ap.add_argument("--threshold", type=int, default=10,
                    help="Falhas por IP para marcar suspeita de brute-force.")
    ap.add_argument("--year", type=int, default=None,
                    help="Ano a assumir (syslog não guarda o ano).")
    args = ap.parse_args(argv)

    stream = sys.stdin if args.path == "-" else open(args.path, "r", encoding="utf-8", errors="replace")
    try:
        events = list(iter_events(stream, year=args.year))
    finally:
        if stream is not sys.stdin:
            stream.close()

    if args.summary:
        print(json.dumps(summarize(events, args.threshold), indent=2, ensure_ascii=False))
    else:
        try:
            for ev in events:
                print(json.dumps(ev, ensure_ascii=False))
        except BrokenPipeError:
            # Ocorre quando a saída é fechada por um pipe (ex.: `| head`).
            sys.stderr.close()
            return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
