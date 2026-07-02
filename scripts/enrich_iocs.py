#!/usr/bin/env python3
"""
enrich_iocs.py
--------------
Enriquece indicadores (IPs) extraídos de eventos de log com contexto útil
para triagem, SEM depender de rede — o que o mantém utilizável em um lab
isolado e evita vazar IOCs para serviços externos por acidente.

O que ele faz hoje (100% offline):
  - classifica o IP (privado, loopback, link-local, reservado, documentação,
    público) usando a biblioteca padrão `ipaddress`;
  - marca IPs de faixas de documentação (RFC 5737 / RFC 3849) como
    "não-roteáveis / provavelmente sintéticos" — útil porque este lab usa
    203.0.113.0/24 nos exemplos;
  - deixa um gancho claro (`REPUTATION_HOOK`) para plugar um feed de
    reputação (AbuseIPDB, OTX, GreyNoise) quando você quiser, sem reescrever
    o resto.

Uso:
    echo '203.0.113.55' | python enrich_iocs.py
    python enrich_iocs.py --ips 203.0.113.55 192.168.56.10 8.8.8.8
    python parse_auth_log.py auth.log --summary | \
        python -c "import json,sys;print('\n'.join(s['source_ip'] for s in json.load(sys.stdin)['suspects']))" | \
        python enrich_iocs.py

Autor: Lucas Stoico Quirino
Licença: MIT
"""

import argparse
import ipaddress
import json
import sys


def classify_ip(ip_str: str) -> dict:
    """Classifica um IP em categorias úteis para triagem, sem rede."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"ip": ip_str, "valid": False, "category": "invalid"}

    # Ordem importa: faixas de documentação também batem em is_private
    # em versões recentes do Python, então checamos documentação primeiro.
    if ip.is_loopback:
        category = "loopback"
    elif ip.is_link_local:
        category = "link_local"
    elif _is_documentation(ip):
        category = "documentation"
    elif ip.is_private:
        category = "private"
    elif ip.is_multicast:
        category = "multicast"
    elif ip.is_reserved:
        category = "reserved"
    else:
        category = "public"

    return {
        "ip": ip_str,
        "valid": True,
        "version": ip.version,
        "category": category,
        "routable": category == "public",
        "note": _note_for(category),
    }


def _is_documentation(ip) -> bool:
    """Faixas reservadas para documentação (RFC 5737 e RFC 3849)."""
    doc_nets = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    ]
    return any(ip in net for net in doc_nets)


def _note_for(category: str) -> str:
    return {
        "loopback": "Tráfego local da própria máquina.",
        "link_local": "Endereço auto-atribuído; não sai da rede local.",
        "private": "RFC 1918 — origem interna do lab (ou rede corporativa).",
        "documentation": "Faixa de documentação (RFC 5737/3849) — sintético, típico de lab.",
        "reserved": "Faixa reservada pela IANA.",
        "multicast": "Endereço multicast.",
        "public": "IP roteável na Internet — candidato a enriquecimento de reputação.",
        "invalid": "Não é um endereço IP válido.",
    }.get(category, "")


def enrich(ip_str: str, reputation_hook=None) -> dict:
    """Classifica e, se um hook de reputação for fornecido, agrega o resultado."""
    result = classify_ip(ip_str)
    if reputation_hook and result.get("routable"):
        # O hook deve receber um IP (str) e retornar um dict serializável.
        # Mantido opcional e desligado por padrão: nada sai para a rede.
        try:
            result["reputation"] = reputation_hook(ip_str)
        except Exception as exc:  # noqa: BLE001 - triagem não pode quebrar por causa de enriquecimento
            result["reputation_error"] = str(exc)
    return result


# Gancho de reputação: deixe como None para operação 100% offline.
# Para ativar, escreva uma função que consulte seu feed preferido e
# atribua-a aqui (ex.: REPUTATION_HOOK = my_abuseipdb_lookup).
REPUTATION_HOOK = None


def main(argv=None):
    ap = argparse.ArgumentParser(description="Enriquece IPs para triagem (offline).")
    ap.add_argument("--ips", nargs="*", help="IPs a enriquecer. Se omitido, lê da stdin.")
    args = ap.parse_args(argv)

    if args.ips:
        ips = args.ips
    else:
        ips = [ln.strip() for ln in sys.stdin if ln.strip()]

    out = [enrich(ip, REPUTATION_HOOK) for ip in ips]
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
