# Blue Team Home Lab — SIEM, Detecção & Simulação de Adversário

Laboratório **self-hosted** de operações de segurança (Blue Team) onde eu gero
os ataques e depois os **detecto, investigo e documento** — rodando o ciclo
completo do analista de SOC: *coletar → parsear → detectar → investigar →
documentar*.

![Arquitetura do lab](docs/images/architecture.svg)

[![Detections](https://img.shields.io/badge/detecções-Sigma-blue)](detections/)
[![MITRE ATT&CK](https://img.shields.io/badge/mapeado-MITRE%20ATT%26CK-red)](detections/README.md)
[![Stack](https://img.shields.io/badge/stack-Elastic%20%7C%20Docker%20%7C%20Python-green)](docker-compose.yml)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## O que este repositório demonstra

- **Engenharia de detecção**: regras [Sigma](detections/sigma) + queries
  [KQL/Elasticsearch](detections/kql/queries.md), mapeadas ao **MITRE ATT&CK**.
- **SIEM na prática**: stack Elastic (Elasticsearch + Kibana) + Filebeat via
  Docker Compose, ingerindo logs de um *attack range*.
- **Automação em Python**: [parsing/normalização ECS](scripts/parse_auth_log.py)
  de `auth.log` com detecção de brute-force por agregação, e
  [enriquecimento de IOCs](scripts/enrich_iocs.py) offline-safe — **com testes**.
- **Metodologia de resposta a incidentes**: cada atividade vira um
  [write-up de incidente](writeups) estruturado, não uma caça à flag.

## Stack

`Elastic Stack (Elasticsearch + Kibana)` · `Filebeat` · `Docker` ·
`Python` · `Sigma` · `MITRE ATT&CK` · `Cyber Kill Chain` ·
`Kali Linux` · `DVWA` · `Wireshark` / `tcpdump`

## Detecções incluídas

| # | Detecção | Tática ATT&CK | Técnica |
|---|----------|---------------|---------|
| 1 | [SSH Brute Force → comprometimento](writeups/001-ssh-brute-force.md) | Credential Access | T1110.001 |
| 2 | [Port Scan (Nmap)](writeups/002-nmap-port-scan.md) | Discovery | T1046 |
| 3 | [SQL Injection em app web](writeups/003-web-sqli.md) | Initial Access | T1190 |

Índice completo com regras e queries: [`detections/`](detections/README.md).

## Quickstart

```bash
git clone https://github.com/LucasStoico/blue-team-home-lab.git
cd blue-team-home-lab
docker compose up -d          # sobe Elastic + Kibana + Filebeat + alvos

# Testar o pipeline sem atacar nada — usando o log de exemplo:
cp data/samples/auth.log.sample data/logs/auth.log
python scripts/parse_auth_log.py data/samples/auth.log.sample --summary
```

Kibana em http://127.0.0.1:5601 · guia completo em [`docs/setup.md`](docs/setup.md).

### Exemplo de saída (detecção de brute-force pelo script)

```json
{
  "source_ip": "203.0.113.55",
  "failed_attempts": 14,
  "distinct_users": ["admin", "root", "oracle", "postgres", "..."],
  "successful_logins": 1,
  "brute_force_suspect": true,
  "credential_stuffing_hint": true
}
```

## Estrutura

```
blue-team-home-lab/
├── docker-compose.yml        # Elastic + Kibana + Filebeat + alvos (DVWA, SSH)
├── config/filebeat/          # config de coleta/ingestão
├── detections/
│   ├── sigma/                # regras Sigma (fonte da verdade, portável)
│   └── kql/                  # queries KQL/DSL para o Kibana
├── writeups/                 # relatórios de incidente (ATT&CK + Kill Chain)
├── scripts/                  # parser ECS + enriquecimento + testes (pytest)
├── data/samples/             # log de exemplo para testar sem atacar
└── docs/                     # arquitetura + setup + diagrama
```

## Rodar os testes

```bash
cd scripts && pip install -r requirements.txt && pytest -v
```

## Aviso

Ambiente de **laboratório isolado e educacional**. Alvos são propositalmente
vulneráveis e a segurança do Elasticsearch está desabilitada para simplificar.
Nunca exponha esta stack à Internet nem reutilize estas configs em produção.
Todos os IPs de exemplo usam faixas de documentação (RFC 5737).

## Autor

**Lucas Stoico Quirino** — SOC / Blue Team · Incident Response · Threat Detection
[LinkedIn](https://linkedin.com/in/lucas-stoico-quirino) · São Paulo, BR · PT/EN (C1)

## Licença

[MIT](LICENSE)
