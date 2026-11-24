# Dashboard local de análise (Streamlit + DuckDB) — design

Status: aguardando aprovação · Data: 2026-11-24 · Frente 2 (a frente 1, dados de 30 dias, já está na `main`)

## 1. Intenção

Hoje, para ver o resultado da pipeline, é preciso abrir um notebook ou rodar SQL no Athena. O dono quer **olhar** os 30 dias de dados:

- uma visão geral por data (quantos casos suspeitos, gráfico de ataques);
- os IPs mais suspeitos;
- um detalhe por aplicação ou por IP.

O dashboard também serve de vitrine do projeto: mostra que a detecção é avaliada contra a verdade e que cada falso positivo tem explicação.

## 2. Objetivos, não-objetivos, anti-objetivos

**Objetivos**

- Rodar localmente com um comando, lendo a pasta `data/` que a DAG já produz.
- Três abas: Visão geral, IPs suspeitos, Detalhe (app ou IP).
- Mostrar lado a lado o que a pipeline marcou (HIGH) e a verdade (`ground_truth`), com precisão e recall.
- Cada falso positivo aparece com o motivo vindo de `benign_events`, e cada ataque que escapou aparece com o seu tipo.

**Não-objetivos (agora)**

- Ler do S3 ou do Athena.
- Deploy público (Streamlit Community Cloud) e login.
- Editar dados, reprocessar ou disparar a DAG pela tela.
- Atualização em tempo real.

**Anti-objetivos (falharia mesmo funcionando)**

- O dashboard recalcular score ou regras. Ele **só lê** o que a pipeline gravou. Se um número da tela divergir de `detection_metrics` ou de `risk_scores`, é bug.
- Quebrar com uma tela vermelha de erro quando ainda não há dados, ou quando falta uma tabela ou um dia.

## 3. Restrições

- Windows com venv (`.venv`) e Docker Desktop. Nada de WSL.
- Não mexer na imagem do Airflow: as dependências do dashboard ficam num arquivo próprio.
- Os dados ficam em `data/<layer>/<table>/dt=YYYY-MM-DD/part-0000.parquet`, com as 10 tabelas listadas no README. Depois do fix `6978d43`, todas são lidas inteiras.
- O CI roda `ruff check .`, `ruff format --check .` e `pytest -q`, e o dashboard precisa passar nos três.

## 4. Abordagens consideradas

| | Abordagem | Trade-off |
|---|---|---|
| **A (escolhida)** | DuckDB consulta os Parquet de bronze/silver/gold na hora | Zero mudança na pipeline e funciona com os 30 dias atuais. Com cerca de 3,8 milhões de eventos, as consultas levam menos de 1 s. |
| B | Nova task na DAG grava tabelas prontas (`gold/dash_*`) | A tela fica instantânea, mas exige mais código na pipeline e um backfill a cada mudança de tela. |
| C | Modelos dbt-duckdb | É um item do roadmap, mas seria uma ferramenta nova para aprender ao mesmo tempo. |

O dono deixou o "como" comigo. Fiquei com A.

## 5. Design

### 5.1 Estrutura

| Arquivo | Papel |
|---|---|
| `src/oauth_shield/dashboard_queries.py` | Todas as consultas, em funções puras `(con, ...) -> DataFrame`. É aqui que mora a lógica e é isto que os testes cobrem. |
| `dashboard/app.py` | Casca Streamlit: lateral, abas, gráficos e tabelas. Não tem SQL próprio, só chama as funções acima. |
| `requirements-dashboard.txt` | `streamlit`, `duckdb`. O Altair já vem junto com o Streamlit. |
| `requirements-dev.txt` | Ganha `duckdb`, para os testes de consulta rodarem no CI. |
| `Dockerfile.dashboard` + serviço `dashboard` no `docker-compose.yaml` | Porta 8501 e `./data` montado só para leitura. Assim `docker compose up` sobe Airflow e dashboard juntos. |
| `tests/test_dashboard_queries.py` | Testes das consultas, sobre Parquet minúsculos gravados com `Storage`. |

Há dois jeitos de rodar:

- `streamlit run dashboard/app.py` no venv, com o ciclo mais rápido para editar;
- ou `docker compose up` e abrir http://localhost:8501.

### 5.2 Camada de dados

`connect(data_dir: str) -> duckdb.DuckDBPyConnection` abre um DuckDB em memória e cria uma **view por tabela que existe em disco**:

```sql
CREATE VIEW risk_scores AS
SELECT * FROM read_parquet('<data_dir>/gold/risk_scores/*/*.parquet',
                           hive_partitioning = true, hive_types = {'dt': DATE});
```

- `dt` vira uma coluna `DATE` em todas as views.
- Uma tabela sem nenhum arquivo não ganha view. `missing_tables(con) -> list[str]` diz quais faltam, e a tela mostra "rode a DAG ou o backfill primeiro (Etapa 2b do COMO_COMECAR)" em vez de quebrar.
- `data_dir` vem da variável `DATA_DIR`, com padrão `data`.
- No Streamlit, a conexão fica em `st.cache_resource`.

**Definições que todas as funções seguem**

- **Marcado:** `risk_level = 'HIGH'`.
- **Ataque real:** o app está em `ground_truth` naquele `dt`.
- **Verdadeiro positivo:** marcado e ataque real. **Falso positivo:** marcado e não é ataque. **Ataque que escapou:** é ataque e não foi marcado. São as mesmas definições de `risk.detection_metrics`.
- **Régua pronta:** `detection_metrics.baseline_ready`.

### 5.3 Lateral (vale para as três abas)

- **Data do dia**, um seletor com as datas de `available_dates(con)`. O padrão é a mais recente.
- **Período**, um intervalo para os gráficos de tendência. O padrão são todas as datas disponíveis.

### 5.4 Aba 1: Visão geral

| Elemento | Função | Conteúdo |
|---|---|---|
| Cartões do dia | `day_summary(con, dt) -> dict` | Apps HIGH, apps MEDIUM, ataques reais, precisão, recall e "régua pronta?". Precisão e recall vêm de `detection_metrics`, sem recálculo. |
| HIGH por dia | `daily_outcomes(con, start, end)` → `dt, outcome, n` | Barras empilhadas por dia: verdadeiros positivos e falsos positivos. A altura total é o número de HIGH. Os dias sem régua pronta ficam marcados. |
| Sinais por dia | `daily_signals(con, start, end)` → `dt, signal, n` | Quantos apps tiveram cada sinal `s_*` disparado. É um gráfico separado, porque um app pode ter vários sinais e empilhar contaria em dobro. |
| Ataques por tipo | `attacks_by_type(con, start, end)` → `attack_type, caught, missed, recall` | Barras horizontais com pegos e escapados por tipo, considerando só os dias com régua pronta. |
| Erros do dia | `day_errors(con, dt)` → `kind, client_id, risk_score, reasons, explanation` | Duas tabelas. Falsos positivos, com `explanation` igual ao `event_type` do `benign_events` ou "sem explicação". Ataques que escaparam, com `explanation` igual ao `attack_type`. |

### 5.5 Aba 2: IPs suspeitos

| Elemento | Função | Conteúdo |
|---|---|---|
| Ranking de IPs | `suspicious_ips(con, start, end, limit=50)` | Sai de `ip_daily`, só com IPs que tiveram falha. Por IP: país, dias em que apareceu, máximo de apps atingidos num dia, total de falhas, % de falha e "atacou um app que era ataque real?". A ordem é apps atingidos desc, depois falhas desc. |
| Subnets fora do usual com erro de scope | `unusual_subnet_scope_errors(con, start, end, min_errors=5)` | É a query 5 do Athena, com um ajuste: só entram os dias com régua pronta, o que resolve a pendência menor da frente 1. A tabela traz dt, app, subnet, erros de scope, sucessos e se o app era ataque real. |

### 5.6 Aba 3: Detalhe

Um botão de rádio escolhe entre **Aplicação** e **IP**.

**Aplicação.** O seletor lista os apps ordenados pelo maior score no período, para os suspeitos aparecerem primeiro.

- `app_timeline(con, client_id, start, end)` traz, por dia:
  - pedidos, sucessos, erros de scope e volume esperado;
  - score, nível e motivos;
  - verdade (`attack_type`, ou o `event_type` benigno, ou vazio).
- O gráfico mostra o volume do dia contra o esperado, e os dias HIGH ficam destacados.
- A tabela por dia traz os motivos.
- `app_subnets(con, client_id, dt)` mostra as subnets do dia (pedidos, sucessos, erros de scope) contra a régua (`is_usual`, `token_share`, `days_seen`). Uma subnet que não está na régua aparece como "nova".

**IP.** É um campo de texto, já preenchido com o primeiro do ranking da aba 2.

- `ip_activity(con, ip, start, end)` sai de `bronze/oauth_events`. Por dia e app, traz pedidos e contagem por status (200, 400, 401), além de país e scopes pedidos.
- Para cada app atingido, mostra se ele era um ataque real naquele dia.

### 5.7 Gráficos

Os gráficos usam Altair, que vem com o Streamlit, para controlar a cor por categoria e marcar os dias sem régua. A paleta e as regras visuais seguem o skill `dataviz` na hora de implementar.

### 5.8 Testes

Uma fixture grava, com `Storage` em `tmp_path`, dois dias minúsculos e conhecidos: alguns apps, um ataque pego, um que escapou, um falso positivo explicado por `benign_events`, um dia sem eventos benignos e um IP que atinge vários apps.

Cada função de 5.4 a 5.6 tem um teste com os números exatos esperados. Além disso:

- `connect` sobre uma pasta vazia: `missing_tables` lista as 10 tabelas e não há exceção;
- `day_summary` bate com a linha de `detection_metrics` do dia;
- `day_errors` traz "sem explicação" para um falso positivo sem `benign_events`;
- `app_subnets` marca como "nova" uma subnet que não está na régua.

O `app.py` não ganha teste automatizado. Ele é verificado subindo o Streamlit, abrindo as três abas com os 30 dias reais e conferindo que os cartões de 2026-11-22 batem com `detection_metrics`.

### 5.9 Documentação

- **README**, seção "Dashboard": como rodar e um print.
- **COMO_COMECAR**, "Etapa 2c: dashboard".
- No roadmap, um item novo marcado como feito.

## 6. Critérios de aceite

1. `streamlit run dashboard/app.py` e `docker compose up` abrem o dashboard em http://localhost:8501 com os 30 dias.
2. Em 2026-11-22, os cartões batem com `detection_metrics` desse dia. Nos 16 dias com régua pronta, a média de precisão é 0,75 e a de recall é 0,78, iguais ao README.
3. A soma de "Ataques por tipo" é igual a TP + FN dos dias com régua pronta, que são 150 + 42.
4. Com `data/` vazia, a tela mostra o aviso e não quebra.
5. `ruff check .`, `ruff format --check .` e `pytest -q` passam.

## 7. Deixado para quem implementa

- O layout fino dentro de cada aba: colunas, ordem dos cartões e textos de ajuda.
- O formato das tabelas e o arredondamento.
- Se o seletor de app mostra também o score máximo no rótulo.
