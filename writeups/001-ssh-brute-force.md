# WU-001 — Brute-force SSH com comprometimento de conta

| Campo | Valor |
|-------|-------|
| **ID** | WU-001 |
| **Severidade** | Alta |
| **Data (lab)** | 2024-03-15 |
| **Alvo** | `victim` (host SSH do lab, container) |
| **Origem** | `203.0.113.55` (faixa de documentação — simulada) |
| **ATT&CK** | [T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) → [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **Kill Chain** | Delivery → Exploitation |
| **Detecção** | [ssh_brute_force.yml](../detections/sigma/ssh_brute_force.yml) |

## Resumo executivo

Um único IP de origem realizou **14 tentativas falhas** de autenticação SSH em
~26 segundos, testando múltiplos nomes de usuário (`admin`, `root`, `oracle`,
`postgres`, `ubuntu`, `deploy`, `jenkins`...), e em seguida obteve **login
bem-sucedido** com a conta `labuser`. O padrão — alta taxa de falhas + alta
cardinalidade de usuários + sucesso imediato do mesmo IP — caracteriza
brute-force seguido de uso de credencial válida.

## Como a atividade foi gerada (lab)

Contra o alvo SSH do lab, a partir do Kali:
```bash
# Ferramenta padrão de auditoria; alvo é o container do próprio lab.
hydra -L users.txt -P rockyou-top100.txt ssh://127.0.0.1:2222 -t 4
```
> Objetivo aqui é **gerar telemetria detectável**, não a técnica ofensiva.
> O foco do write-up é a resposta defensiva.

## Timeline (evidência)

Extraído de `data/samples/auth.log.sample`:

```
08:22:14  Invalid user admin from 203.0.113.55
08:22:14  Failed password for invalid user admin from 203.0.113.55
08:22:16  Failed password for invalid user root  from 203.0.113.55
...        (mais 11 falhas, usuários variados)
08:22:27  Accepted password for labuser from 203.0.113.55   <-- COMPROMETIMENTO
```

Resumo agregado gerado pelo script do repositório:
```bash
python scripts/parse_auth_log.py data/samples/auth.log.sample --summary
```
```json
{
  "source_ip": "203.0.113.55",
  "failed_attempts": 14,
  "distinct_users": ["admin","deploy","git","jenkins","labuser","oracle","postgres","root","test","ubuntu"],
  "successful_logins": 1,
  "brute_force_suspect": true,
  "credential_stuffing_hint": true
}
```

## Lógica de detecção

Sigma (resumo): `event.action = ssh_login_failed`, agrupado por `source.ip`,
`count() > 10` em janela de 5 min. O sinal de maior severidade é a **correlação
temporal**: um `ssh_login_success` do mesmo IP dentro de ~1 min após a rajada
(ver [Query 2](../detections/kql/queries.md)).

## Impacto

- Conta `labuser` comprometida via senha fraca (`labuser:labuser`).
- Acesso interativo obtido → risco de persistência, escalonamento e movimento
  lateral a partir deste ponto.

## Resposta / Remediação

1. **Contenção**: encerrar sessões ativas do IP; bloquear `203.0.113.55` no firewall.
2. **Erradicação**: rotacionar a credencial de `labuser`; auditar chaves SSH
   autorizadas e criação de contas/cron após 08:22:27.
3. **Recuperação**: reativar acesso só após validação.
4. **Hardening**:
   - desabilitar autenticação por senha (`PasswordAuthentication no`), usar chaves;
   - `fail2ban` / rate-limit no SSH;
   - remover exposição direta do SSH; usar bastion/VPN;
   - política de senha forte + MFA.

## Lições aprendidas

- Senha fraca + SSH exposto = comprometimento em segundos. A detecção precisa
  disparar **na rajada de falhas**, não só no sucesso — a janela de resposta é curtíssima.
- O valor do alerta cresce muito quando ele **correlaciona** falha→sucesso do
  mesmo IP, em vez de olhar cada evento isolado.
