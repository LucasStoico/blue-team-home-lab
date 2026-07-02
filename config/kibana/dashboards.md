# Dashboards do Kibana

Este lab foca em detecção via Sigma/KQL. Para dashboards, sugestão de painéis a
montar em **Kibana → Dashboard** sobre o índice `lab-logs-*`:

1. **Falhas de autenticação SSH por IP de origem** (bar chart, agg em `source.ip`)
2. **Falhas x sucessos ao longo do tempo** (line chart, split por `event.outcome`)
3. **Top usuários visados** (data table, agg em `user.name` filtrando falhas)
4. **Mapa de origem dos IPs públicos** (se enriquecido com geo)

Depois de montar, exporte via **Stack Management → Saved Objects → Export** e
versione o `.ndjson` aqui para que qualquer um reproduza os painéis.
