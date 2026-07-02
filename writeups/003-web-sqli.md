# WU-003 — Tentativa de SQL Injection em aplicação web

| Campo | Valor |
|-------|-------|
| **ID** | WU-003 |
| **Severidade** | Alta |
| **Data (lab)** | 2024-03-17 |
| **Alvo** | DVWA (`http://127.0.0.1:8080`) |
| **Origem** | Kali Linux do lab |
| **ATT&CK** | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) · OWASP A03 Injection |
| **Kill Chain** | Exploitation |
| **Detecção** | [web_sqli_attempt.yml](../detections/sigma/web_sqli_attempt.yml) |

## Resumo executivo

Requisições HTTP ao alvo web continham payloads clássicos de SQL injection na
query string (`' OR '1'='1`, `UNION SELECT`, referência a `information_schema`).
Indica tentativa de exploração da camada de aplicação para burlar autenticação
ou extrair dados do banco.

## Como a atividade foi gerada (lab)

Manualmente contra o módulo de SQL Injection do DVWA e/ou com scanner de app
web apontado ao alvo local do lab. O objetivo é produzir **entradas de access
log** com os padrões de injeção para exercitar a detecção.

## O que observar no log

No access log do servidor web, a `url.query` (ou `url.original`) carrega o
payload. Exemplos de assinaturas monitoradas:

- `' OR '1'='1` e variações → bypass de condição
- `UNION SELECT` / `UNION ALL SELECT` → extração de colunas
- `information_schema` → enumeração de esquema
- `SLEEP(` → injeção baseada em tempo (blind)
- `-- ` e `/*` → comentários para truncar a query original

Query de referência: [Query 5](../detections/kql/queries.md#5-tentativa-de-sql-injection-em-log-web-dvwaapache).

## Contexto de desenvolvimento

No meu projeto acadêmico de e-commerce full-stack fui responsável pelos fluxos
de autenticação e input, revisando a aplicação contra o OWASP Top 10. Isso me
dá os dois lados: sei **onde** a query mal parametrizada nasce no código e
**como** ela aparece no log quando alguém tenta abusá-la — o que torna a
detecção (e a recomendação de correção) mais precisa.

## Resposta / Remediação

1. **Detectar e bloquear** a origem; WAF com regras contra injeção.
2. **Corrigir a raiz**: prepared statements / queries parametrizadas; validação
   e sanitização de input; princípio do menor privilégio no usuário do banco.
3. **Verificar impacto**: houve resposta 200 com volume anômalo de dados? Sinal
   de extração bem-sucedida — tratar como possível vazamento.

## Lições aprendidas

- Detecção por assinatura na query string pega o óbvio, mas evasões (encoding,
  case, comentários inline) exigem normalização do input antes da regra —
  próximo incremento do lab.
- A detecção mais valiosa correlaciona a **tentativa** (payload no log) com o
  **sucesso** (resposta anômala), do mesmo jeito que o WU-001 correlaciona
  falha→sucesso no SSH.
