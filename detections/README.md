# Detecções

Cada detecção deste lab tem duas representações:

- **Regra Sigma** (`sigma/`) — formato aberto e independente de fornecedor,
  a "fonte da verdade". Pode ser convertida para Elastic, Splunk, Sentinel etc.
  com o [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli).
- **Query KQL / Elasticsearch DSL** (`kql/`) — a implementação executável
  neste SIEM (Elastic Stack), pronta para virar alerta no Kibana.

## Cobertura (mapeamento MITRE ATT&CK)

| # | Detecção | Tática | Técnica | Sigma | Query |
|---|----------|--------|---------|-------|-------|
| 1 | SSH Brute Force | Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | [ssh_brute_force.yml](sigma/ssh_brute_force.yml) | [Q1](kql/queries.md#1-brute-force-ssh--falhas-por-ip-de-origem) |
| 2 | Login após rajada de falhas | Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) | — (correlação) | [Q2](kql/queries.md#2-login-bem-sucedido-logo-após-rajada-de-falhas-mesmo-ip) |
| 3 | Enumeração de usuários SSH | Reconnaissance | [T1589](https://attack.mitre.org/techniques/T1589/) | (via Q3) | [Q3](kql/queries.md#3-enumeração-de-usuários-invalid-user) |
| 4 | Port Scan (Nmap) | Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | [nmap_port_scan.yml](sigma/nmap_port_scan.yml) | [Q4](kql/queries.md#4-port-scan--muitas-portas-de-destino-por-origem) |
| 5 | SQL Injection em app web | Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) | [web_sqli_attempt.yml](sigma/web_sqli_attempt.yml) | [Q5](kql/queries.md#5-tentativa-de-sql-injection-em-log-web-dvwaapache) |

## Metodologia

Cada detecção nasce do mesmo ciclo, documentado nos [write-ups](../writeups):

1. **Gerar telemetria** — executar a atividade contra um alvo do lab (SSH, DVWA).
2. **Observar o log cru** — o que exatamente apareceu no `auth.log` / access log?
3. **Escrever a lógica** — expressar o padrão em Sigma e testar a query no Kibana.
4. **Reduzir ruído** — iterar para separar sinal de falso positivo.
5. **Documentar** — registrar como incidente, mapeando ao ATT&CK e à Kill Chain.
