# Write-ups de Incidente

Cada máquina/atividade deste lab é documentada como um **relatório de incidente**,
não como caça à flag. A estrutura é consistente: resumo executivo → como a
telemetria foi gerada → timeline com evidência → lógica de detecção → impacto →
resposta/remediação → lições aprendidas, sempre mapeando ao MITRE ATT&CK e à
Cyber Kill Chain.

| # | Write-up | Severidade | ATT&CK |
|---|----------|-----------|--------|
| 001 | [Brute-force SSH com comprometimento](001-ssh-brute-force.md) | Alta | T1110.001 → T1078 |
| 002 | [Port scan (Nmap) — reconhecimento](002-nmap-port-scan.md) | Média | T1046 |
| 003 | [SQL Injection em app web](003-web-sqli.md) | Alta | T1190 |

> Esta é a metodologia que aplico também no HackTheBox e no TryHackMe: cada box
> vira um write-up estruturado (recon → enumeração → exploração →
> pós-exploração → lições), tratado como investigação, não como flag.
