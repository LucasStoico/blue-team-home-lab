# Queries de Detecção — KQL & Elasticsearch DSL

Queries prontas para colar no **Kibana → Discover** (KQL) e no **Dev Tools**
(DSL). Índice de referência: `lab-logs-*`.

---

## 1. Brute-force SSH — falhas por IP de origem

**KQL (Discover):**
```
event.action : "ssh_login_failed" and source.ip : *
```

**Elasticsearch DSL — top IPs por número de falhas (últimos 15 min):**
```json
POST lab-logs-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.action": "ssh_login_failed" } },
        { "range": { "@timestamp": { "gte": "now-15m" } } }
      ]
    }
  },
  "aggs": {
    "por_ip": {
      "terms": { "field": "source.ip", "size": 10, "order": { "_count": "desc" } },
      "aggs": {
        "usuarios_distintos": { "cardinality": { "field": "user.name" } }
      }
    }
  }
}
```
> Leitura do analista: um IP com muitas falhas **e** alta cardinalidade de
> usuários = spray de credenciais. Se logo depois houver um
> `ssh_login_success` do mesmo IP → possível comprometimento.

---

## 2. Login bem-sucedido logo após rajada de falhas (mesmo IP)

**KQL:**
```
event.action : "ssh_login_success" and source.ip : "203.0.113.55"
```
Correlacione o `@timestamp` do sucesso com a janela das falhas do mesmo
`source.ip` (query 1). Sucesso dentro de ~1 min após 10+ falhas é o sinal de
maior severidade da cadeia.

---

## 3. Enumeração de usuários (Invalid user)

**KQL:**
```
event.action : "ssh_invalid_user"
```
Muitos `Invalid user` de um mesmo IP indicam que o atacante está adivinhando
nomes de conta (root, admin, oracle, postgres...) — reconhecimento pré-ataque.

---

## 4. Port scan — muitas portas de destino por origem

**Elasticsearch DSL:**
```json
POST lab-logs-*/_search
{
  "size": 0,
  "query": { "range": { "@timestamp": { "gte": "now-5m" } } },
  "aggs": {
    "scanners": {
      "terms": { "field": "source.ip", "size": 10 },
      "aggs": {
        "portas_distintas": { "cardinality": { "field": "destination.port" } },
        "so_scanners": {
          "bucket_selector": {
            "buckets_path": { "portas": "portas_distintas" },
            "script": "params.portas > 100"
          }
        }
      }
    }
  }
}
```

---

## 5. Tentativa de SQL injection em log web (DVWA/Apache)

**KQL:**
```
url.query : (*UNION*SELECT* or *OR*1=1* or *information_schema* or *SLEEP(*)
```
> Ajuste os nomes de campo conforme o parser/ingest do seu Apache access log.
> No lab, o alvo é o DVWA em `http://127.0.0.1:8080`.

---

### Como transformar em alerta

No Kibana: **Stack Management → Rules → Create rule → Elasticsearch query**,
cole a DSL correspondente, defina o limiar (ex.: `count > 10`) e a janela
(`5m`), e conecte a uma ação (log/e-mail/webhook). Cada regra aqui tem um
equivalente Sigma em [`../sigma/`](../sigma) — o Sigma é a fonte da verdade
independente de fornecedor; o KQL/DSL é a implementação neste SIEM.
