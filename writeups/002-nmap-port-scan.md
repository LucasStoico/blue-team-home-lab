# WU-002 — Reconhecimento de rede via port scan (Nmap)

| Campo | Valor |
|-------|-------|
| **ID** | WU-002 |
| **Severidade** | Média |
| **Data (lab)** | 2024-03-16 |
| **Alvo** | Sub-rede do lab (`btl` bridge) |
| **Origem** | Kali Linux do lab |
| **ATT&CK** | [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/) |
| **Kill Chain** | Reconnaissance |
| **Detecção** | [nmap_port_scan.yml](../detections/sigma/nmap_port_scan.yml) |

## Resumo executivo

Um host de origem tocou um grande número de **portas de destino distintas** em
poucos hosts, num intervalo de segundos — assinatura de varredura de portas.
Sozinho, reconhecimento não é comprometimento, mas costuma ser o primeiro passo
da Cyber Kill Chain e é um bom gatilho precoce de alerta.

## Como a atividade foi gerada (lab)

```bash
# Varredura SYN das 1000 portas mais comuns nos alvos do lab.
nmap -sS -T4 <alvo-do-lab>
```

## O que observar no log

Muitas conexões/fluxos do mesmo `source.ip` para várias `destination.port`
em janela curta. A detecção conta **portas de destino distintas por IP de
origem** e dispara acima do limiar (ex.: > 100 portas em 1 min).

Query de referência: [Query 4](../detections/kql/queries.md#4-port-scan--muitas-portas-de-destino-por-origem).

## Lógica de detecção

Sigma: agregação `count(destination.port) by source.ip > 100` em 1 min.
Ajuste o limiar à sua baseline — scanners de vulnerabilidade autorizados
produzem o mesmo padrão e são o principal falso positivo.

## Resposta / Remediação

1. Verificar se a origem é um scanner **autorizado** (janela/agenda aprovada).
2. Se não autorizado: bloquear a origem, elevar monitoramento sobre os alvos
   varridos e observar tentativas de exploração subsequentes (a varredura
   costuma preceder o ataque real).
3. Hardening: reduzir superfície exposta, segmentar rede, IDS/IPS na borda.

## Lições aprendidas

- Reconhecimento é barato de detectar e dá **tempo de reação** antes da
  exploração — vale a pena alertar cedo, mesmo com severidade média.
- O ponto de esforço é a **baseline**: sem conhecer o "normal" da rede, o
  limiar gera ruído. Detecção boa é tanto engenharia de limiar quanto de padrão.
