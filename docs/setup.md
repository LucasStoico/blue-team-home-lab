# Setup

> ⚠️ **Ambiente de laboratório isolado.** A stack sobe com a segurança do
> Elasticsearch desabilitada e com alvos propositalmente vulneráveis. Rode em
> uma VM/rede isolada, **nunca** exposta à Internet. As portas já estão
> vinculadas a `127.0.0.1` no `docker-compose.yml` para reduzir risco.

## Pré-requisitos

- Docker + Docker Compose
- ~4 GB de RAM livres (o Elasticsearch pede memória)
- Linux/macOS/WSL2. No Linux, ajuste o `vm.max_map_count`:
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  ```

## 1. Subir a stack

```bash
git clone https://github.com/LucasStoico/blue-team-home-lab.git
cd blue-team-home-lab
docker compose up -d
```

Aguarde ~1–2 min e acesse:
- **Kibana**: http://127.0.0.1:5601
- **Elasticsearch**: http://127.0.0.1:9200
- **DVWA** (alvo web): http://127.0.0.1:8080
- **SSH** (alvo): `ssh labuser@127.0.0.1 -p 2222` (senha `labuser`)

## 2. Testar o pipeline SEM atacar nada (recomendado para começar)

O repositório já traz um log de exemplo. Copie-o para a pasta que o Filebeat
observa e veja os dados aparecerem no Kibana:

```bash
cp data/samples/auth.log.sample data/logs/auth.log
```

No Kibana → **Discover**, crie um data view para `lab-logs-*` e filtre:
```
event.action : "ssh_login_failed"
```

Antes mesmo do SIEM, os scripts locais já entregam a análise:
```bash
# Resumo de brute-force por IP
python scripts/parse_auth_log.py data/samples/auth.log.sample --summary

# Eventos normalizados em JSON/ECS
python scripts/parse_auth_log.py data/samples/auth.log.sample | head

# Enriquecimento (offline) dos IPs suspeitos
python scripts/parse_auth_log.py data/samples/auth.log.sample --summary \
  | python -c "import json,sys;print('\n'.join(s['source_ip'] for s in json.load(sys.stdin)['suspects']))" \
  | python scripts/enrich_iocs.py
```

## 3. Gerar telemetria real (opcional, para quem quer o loop completo)

A partir de um Kali (ou de qualquer host na rede do lab), execute atividades
padrão de auditoria **contra os alvos do próprio lab** para produzir logs, e
então cace-as no Kibana usando as [queries](../detections/kql/queries.md):

- Brute-force SSH → gera `auth.log` → detecção [WU-001](../writeups/001-ssh-brute-force.md)
- Port scan → detecção [WU-002](../writeups/002-nmap-port-scan.md)
- SQL injection no DVWA → detecção [WU-003](../writeups/003-web-sqli.md)

## 4. Transformar queries em alertas

Kibana → **Stack Management → Rules → Create rule → Elasticsearch query**.
Cole a DSL da query, defina limiar e janela, conecte uma ação. Cada regra tem
seu equivalente Sigma em [`detections/sigma`](../detections/sigma).

## Encerrar

```bash
docker compose down          # mantém os dados
docker compose down -v        # remove também o volume do Elasticsearch
```

## Troubleshooting

- **Elasticsearch reinicia/morre**: quase sempre é `vm.max_map_count` ou RAM.
- **Sem dados no Kibana**: confira se há arquivos em `data/logs/` e veja
  `docker compose logs filebeat`.
- **Porta ocupada**: ajuste os mapeamentos em `docker-compose.yml`.
