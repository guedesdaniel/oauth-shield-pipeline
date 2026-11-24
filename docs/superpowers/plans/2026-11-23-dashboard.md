# Dashboard local (Streamlit + DuckDB) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dashboard local com três abas (Visão geral, IPs suspeitos, Detalhe) sobre os Parquet de `data/`, sem recalcular nada da pipeline.

**Architecture:** `src/oauth_shield/dashboard_queries.py` cria um DuckDB em memória com uma view por tabela em disco e expõe funções puras `(con, ...) -> DataFrame | dict`, todas testadas com um mini-dataset de dois dias. `dashboard/app.py` é só a casca Streamlit e Altair que chama essas funções. Um serviço `dashboard` no docker compose roda o mesmo app na porta 8501.

**Tech Stack:** Python 3.12, DuckDB ≥ 1.1 (o venv tem a 2.0.1), Streamlit ≥ 1.40 (o venv tem a 1.67), Altair (vem com o Streamlit), pytest, ruff.

**Spec:** docs/superpowers/specs/2026-11-23-dashboard-design.md

## Global Constraints

- O dashboard **só lê**. Ele nunca recalcula score, regra ou métrica. Precisão e recall vêm de `detection_metrics`.
- Definições: **marcado** = `risk_level = 'HIGH'`; **ataque real** = `client_id` em `ground_truth` do mesmo `dt`; **régua pronta** = `detection_metrics.baseline_ready`.
- Toda função recebe datas como `'YYYY-MM-DD'`, com intervalos `start`/`end` inclusivos, e devolve `dt` como string `'YYYY-MM-DD'`.
- As views usam `read_parquet('<data_dir>/<layer>/<table>/*/*.parquet', hive_partitioning = true, hive_types = {'dt': DATE})`. Uma tabela sem nenhum arquivo não ganha view.
- `DATA_DIR` vem do ambiente, com padrão `data`.
- A imagem do Airflow não muda. As dependências ficam em `requirements-dashboard.txt` (`streamlit>=1.40`, `duckdb>=1.1`), e `requirements-dev.txt` ganha `duckdb>=1.1`.
- O CI precisa passar `ruff check .`, `ruff format --check .` e `pytest -q`.
- Os textos da tela ficam em PT-BR. O README fica em inglês e o `COMO_COMECAR.md` em PT-BR.

## Review Focus

1. **`data/` vazia ou faltando tabela:** a tela mostra o aviso da Etapa 2b e não quebra. Teste: `test_missing_tables_on_empty_dir` (Task 1). A verificação do app é manual (Task 5).
2. **Dia com `benign_events` vazio:** o falso positivo sai como "sem explicação", sem erro de tipo. Teste: `test_day_errors_unexplained_fp` (Task 2).
3. **Partição vazia do baseline no primeiro dia:** a view de `client_subnet_baseline` lê tudo. Teste: a fixture grava D1 com `build_baseline(pd.DataFrame(), 0)` e `test_app_subnets_status` (Task 4) consulta a view.
4. **Período de um dia só (`start == end`):** as funções funcionam. Teste: `test_daily_outcomes_single_day` (Task 2).
5. **IP digitado que não existe, ou app sem dados:** a função devolve um DataFrame vazio com as colunas, e a tela mostra "nenhum dado". Testes: `test_ip_activity_unknown_ip` (Task 3) e `test_app_timeline_unknown_app` (Task 4).

## Mini-dataset de teste (fixture `dash`, em `tests/test_dashboard_queries.py`)

`D1 = "2026-11-01"` (régua não pronta) e `D2 = "2026-11-02"` (régua pronta), gravados com `Storage(backend="local", data_dir=tmp_path)`. As colunas `s_*` são as de `risk.WEIGHTS`, e o que não está listado abaixo é `False`.

| Tabela | D1 | D2 |
|---|---|---|
| risk_scores (client_id, risk_score, risk_level, reasons, s_*) | a 80 HIGH (s_scope_probing, s_foreign_geo); b 40 HIGH (s_foreign_geo); c 25 MEDIUM (s_volume_burst); d 0 LOW | a 0 LOW; b 40 HIGH (s_new_subnet_scope_errors); c 65 HIGH (s_volume_burst, s_suspicious_ip); d 0 LOW |
| ground_truth (client_id, attack_type) | a scope_probing; d credential_stuffing | c volume_burst |
| benign_events (client_id, event_type, subnet, notified) | b foreign_region | vazio, com as 4 colunas |
| detection_metrics | run_date D1, flagged 2, tp 1, fp 1, fn 1, precision 0.5, recall 0.5, baseline_ready False | run_date D2, flagged 2, tp 1, fp 1, fn 0, precision 0.5, recall 1.0, baseline_ready True |
| client_daily (client_id, total_requests, success_count, invalid_scope_count, expected_daily_volume) | a 100/80/20/100; b 50/50/0/50; c 300/300/0/100; d 30/0/0/40 | a 100/100/0/100; b 56/50/6/50; c 400/395/0/100; d 40/40/0/40 |
| ip_daily (source_ip, country, total_requests, failed_requests, distinct_clients) | 9.9.9.9 BR 30/30/3; 1.1.1.1 BR 100/0/1 | 9.9.9.9 BR 10/5/2 |
| oauth_events (event_id, event_ts, client_id, source_ip, country, requested_scope, status_code) | 9.9.9.9 → a, b, d com 10 × 401 cada; 1.1.1.1 → a com 100 × 200 | 9.9.9.9 → b com 5 × 200 e c com 5 × 401 |
| client_subnet_daily (client_id, subnet, total_requests, success_count, invalid_scope_count, distinct_ips) | b 7.7.7.0/24 9/0/9/1 | b 1.1.1.0/24 50/50/0/2; b 5.5.5.0/24 6/0/6/1 |
| client_subnet_baseline | `baseline.build_baseline(pd.DataFrame(), 0)` (vazio) | b 1.1.1.0/24: window_tokens 50, token_share 1.0, days_seen 1, is_usual True, window_days_available 14 |
| client_profile | não é usada pelo dashboard; a fixture grava 1 linha (a) só para `missing_tables` não acusar | idem |

---

### Task 0: Dependências

**Files:**
- Create: `requirements-dashboard.txt`
- Modify: `requirements-dev.txt`

- [ ] **Step 1:** Criar `requirements-dashboard.txt` com `-r requirements.txt`, `streamlit>=1.40` e `duckdb>=1.1`. Acrescentar `duckdb>=1.1` em `requirements-dev.txt`.
- [ ] **Step 2:** Rodar `.venv\Scripts\python.exe -m pip install -r requirements-dashboard.txt -r requirements-dev.txt`. Expected: instala sem erro, e `python -c "import duckdb, streamlit"` funciona.
- [ ] **Step 3:** Commit: `chore: dashboard dependencies`.

### Task 1: Conexão, tabelas que faltam e datas

**Files:**
- Create: `src/oauth_shield/dashboard_queries.py`, `tests/test_dashboard_queries.py`

**Interfaces:**
- Produces:
  - `TABLES: dict[str, str]`, de tabela para layer, com as 10 tabelas: oauth_events, client_profile, ground_truth e benign_events em bronze; client_daily, ip_daily, client_subnet_daily e client_subnet_baseline em silver; risk_scores e detection_metrics em gold.
  - `SIGNALS: list[str]` = `list(risk.WEIGHTS)`.
  - `connect(data_dir: str | Path) -> duckdb.DuckDBPyConnection`.
  - `missing_tables(con) -> list[str]`, na ordem de `TABLES`.
  - `available_dates(con) -> list[str]`, em ordem crescente, a partir de `detection_metrics`.
- `connect` guarda o resultado da checagem de arquivos em `con` (por exemplo, numa tabela temporária `_missing`) ou numa variável de módulo associada. A escolha é livre, desde que `missing_tables` responda sem reler o disco.

- [ ] **Step 1: Testes que falham**, incluindo a fixture `dash` (a tabela acima) e:

```python
def test_missing_tables_on_empty_dir(tmp_path):
    con = dq.connect(tmp_path)
    assert dq.missing_tables(con) == list(dq.TABLES)

def test_connect_full_dataset(dash):
    con = dq.connect(dash)
    assert dq.missing_tables(con) == []
    assert dq.available_dates(con) == ["2026-11-01", "2026-11-02"]
```

- [ ] **Step 2:** `pytest tests/test_dashboard_queries.py -q`. Expected: FAIL, com `ModuleNotFoundError` ou `AttributeError` de `dashboard_queries`.
- [ ] **Step 3:** Implementar `TABLES`, `SIGNALS`, `connect`, `missing_tables` e `available_dates`. Use `glob` para decidir se a tabela tem arquivo e escape as aspas simples no caminho do SQL.
- [ ] **Step 4:** Rodar de novo. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(dashboard): duckdb views over the parquet layers`.

### Task 2: Consultas da Visão geral

**Files:** Modify `src/oauth_shield/dashboard_queries.py` e `tests/test_dashboard_queries.py`.

**Interfaces (Produces):**
- `day_summary(con, dt) -> dict`, com as chaves `high`, `medium`, `attacks`, `precision`, `recall`, `baseline_ready`.
- `daily_outcomes(con, start, end) -> DataFrame[dt, outcome, n, baseline_ready]`:
  - `outcome` ∈ {"ataque real", "falso positivo"};
  - só linhas com `n > 0`;
  - ordem por `dt` e `outcome`.
- `daily_signals(con, start, end) -> DataFrame[dt, signal, n]`:
  - conta apps de qualquer nível com o sinal `True`;
  - só `n > 0`;
  - ordem por `dt` e `signal`.
- `attacks_by_type(con, start, end) -> DataFrame[attack_type, caught, missed, recall]`:
  - só dias com régua pronta;
  - `caught` = ataque marcado HIGH;
  - ordem por `recall` crescente e `attack_type`.
- `day_errors(con, dt) -> DataFrame[kind, client_id, risk_score, reasons, explanation]`:
  - `kind` ∈ {"falso positivo", "ataque que escapou"};
  - para FP, `explanation` = `event_type` do `benign_events` (vários separados por ", ") ou "sem explicação";
  - para FN, `explanation` = `attack_type`;
  - ordem por `kind` e `risk_score` decrescente.

- [ ] **Step 1: Testes que falham**

```python
def test_day_summary(dash):
    s = dq.day_summary(dq.connect(dash), "2026-11-01")
    assert s == {"high": 2, "medium": 1, "attacks": 2, "precision": 0.5, "recall": 0.5, "baseline_ready": False}

def test_daily_outcomes(dash):
    df = dq.daily_outcomes(dq.connect(dash), "2026-11-01", "2026-11-02")
    assert df.to_dict("records") == [
        {"dt": "2026-11-01", "outcome": "ataque real", "n": 1, "baseline_ready": False},
        {"dt": "2026-11-01", "outcome": "falso positivo", "n": 1, "baseline_ready": False},
        {"dt": "2026-11-02", "outcome": "ataque real", "n": 1, "baseline_ready": True},
        {"dt": "2026-11-02", "outcome": "falso positivo", "n": 1, "baseline_ready": True},
    ]

def test_daily_outcomes_single_day(dash):  # Review Focus 4
    assert len(dq.daily_outcomes(dq.connect(dash), "2026-11-02", "2026-11-02")) == 2

def test_daily_signals(dash):
    df = dq.daily_signals(dq.connect(dash), "2026-11-01", "2026-11-02")
    got = {(r.dt, r.signal): r.n for r in df.itertuples()}
    assert got == {
        ("2026-11-01", "s_foreign_geo"): 2, ("2026-11-01", "s_scope_probing"): 1,
        ("2026-11-01", "s_volume_burst"): 1, ("2026-11-02", "s_new_subnet_scope_errors"): 1,
        ("2026-11-02", "s_suspicious_ip"): 1, ("2026-11-02", "s_volume_burst"): 1,
    }

def test_attacks_by_type_only_ready_days(dash):
    df = dq.attacks_by_type(dq.connect(dash), "2026-11-01", "2026-11-02")
    assert df.to_dict("records") == [{"attack_type": "volume_burst", "caught": 1, "missed": 0, "recall": 1.0}]

def test_day_errors_explained(dash):
    df = dq.day_errors(dq.connect(dash), "2026-11-01")
    assert df[["kind", "client_id", "explanation"]].to_dict("records") == [
        {"kind": "ataque que escapou", "client_id": "d", "explanation": "credential_stuffing"},
        {"kind": "falso positivo", "client_id": "b", "explanation": "foreign_region"},
    ]

def test_day_errors_unexplained_fp(dash):  # Review Focus 2
    df = dq.day_errors(dq.connect(dash), "2026-11-02")
    assert df[["kind", "client_id", "explanation"]].to_dict("records") == [
        {"kind": "falso positivo", "client_id": "b", "explanation": "sem explicação"}
    ]
```

- [ ] **Step 2:** Rodar. Expected: FAIL com `AttributeError`.
- [ ] **Step 3:** Implementar as cinco funções em SQL DuckDB, com `?` como parâmetro e `strftime(dt, '%Y-%m-%d') AS dt`. Garantir tipos Python nativos no dict de `day_summary` (`int`, `float`, `bool`).
- [ ] **Step 4:** Rodar. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(dashboard): overview queries`.

### Task 3: Consultas de IP

**Interfaces (Produces):**
- `suspicious_ips(con, start, end, limit=50) -> DataFrame[source_ip, country, days_seen, max_clients, failed, total, fail_ratio, hit_real_attack]`:
  - só IPs com `failed_requests > 0` em algum dia do período;
  - `fail_ratio` = failed / total, arredondado a 3 casas;
  - `hit_real_attack` vem de `oauth_events` (IP, dt, app) cruzado com `ground_truth` do mesmo dt;
  - ordem por `max_clients` desc, `failed` desc e `source_ip`.
- `unusual_subnet_scope_errors(con, start, end, min_errors=5) -> DataFrame[dt, client_id, subnet, invalid_scope_count, success_count, total_requests, is_attack]`:
  - só dias com régua pronta;
  - a subnet não está na régua do dia ou tem `is_usual = false`;
  - ordem por `dt` desc e `invalid_scope_count` desc.
- `ip_activity(con, ip, start, end) -> DataFrame[dt, client_id, requests, s200, s400, s401, countries, scopes, is_attack]`:
  - `countries` e `scopes` são os valores distintos separados por ", ";
  - ordem por `dt` e `client_id`.

- [ ] **Step 1: Testes que falham**

```python
def test_suspicious_ips(dash):
    df = dq.suspicious_ips(dq.connect(dash), "2026-11-01", "2026-11-02")
    assert df.to_dict("records") == [{"source_ip": "9.9.9.9", "country": "BR", "days_seen": 2, "max_clients": 3,
                                      "failed": 35, "total": 40, "fail_ratio": 0.875, "hit_real_attack": True}]

def test_unusual_subnet_scope_errors_ready_days_only(dash):
    df = dq.unusual_subnet_scope_errors(dq.connect(dash), "2026-11-01", "2026-11-02")
    assert df[["dt", "client_id", "subnet", "invalid_scope_count", "is_attack"]].to_dict("records") == [
        {"dt": "2026-11-02", "client_id": "b", "subnet": "5.5.5.0/24", "invalid_scope_count": 6, "is_attack": False}
    ]  # D1 (7.7.7.0/24, 9 erros) fica de fora: régua não pronta

def test_ip_activity(dash):
    df = dq.ip_activity(dq.connect(dash), "9.9.9.9", "2026-11-01", "2026-11-02")
    assert df[["dt", "client_id", "requests", "s200", "s401", "is_attack"]].to_dict("records") == [
        {"dt": "2026-11-01", "client_id": "a", "requests": 10, "s200": 0, "s401": 10, "is_attack": True},
        {"dt": "2026-11-01", "client_id": "b", "requests": 10, "s200": 0, "s401": 10, "is_attack": False},
        {"dt": "2026-11-01", "client_id": "d", "requests": 10, "s200": 0, "s401": 10, "is_attack": True},
        {"dt": "2026-11-02", "client_id": "b", "requests": 5, "s200": 5, "s401": 0, "is_attack": False},
        {"dt": "2026-11-02", "client_id": "c", "requests": 5, "s200": 0, "s401": 5, "is_attack": True},
    ]

def test_ip_activity_unknown_ip(dash):  # Review Focus 5
    df = dq.ip_activity(dq.connect(dash), "0.0.0.0", "2026-11-01", "2026-11-02")
    assert df.empty and "is_attack" in df.columns
```

- [ ] **Step 2:** Rodar. Expected: FAIL com `AttributeError`.
- [ ] **Step 3:** Implementar as três funções.
- [ ] **Step 4:** Rodar. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(dashboard): ip and subnet queries`.

### Task 4: Consultas de Detalhe do app

**Interfaces (Produces):**
- `app_options(con, start, end) -> DataFrame[client_id, max_score]`, em ordem de `max_score` desc e `client_id`.
- `app_timeline(con, client_id, start, end) -> DataFrame[dt, total_requests, success_count, invalid_scope_count, expected_daily_volume, risk_score, risk_level, reasons, truth]`:
  - `truth` = `attack_type`, ou `event_type` benigno, ou `None`;
  - ordem por `dt`.
- `app_subnets(con, client_id, dt) -> DataFrame[subnet, total_requests, success_count, invalid_scope_count, baseline_status, token_share, days_seen]`:
  - `baseline_status` ∈ {"usual", "fora do usual", "nova"}, onde "nova" significa que a subnet não está na régua do dia;
  - ordem por `total_requests` desc.

- [ ] **Step 1: Testes que falham**

```python
def test_app_options(dash):
    df = dq.app_options(dq.connect(dash), "2026-11-01", "2026-11-02")
    assert list(df["client_id"]) == ["a", "c", "b", "d"] and list(df["max_score"]) == [80, 65, 40, 0]

def test_app_timeline(dash):
    df = dq.app_timeline(dq.connect(dash), "c", "2026-11-01", "2026-11-02")
    assert df[["dt", "risk_level", "truth"]].to_dict("records") == [
        {"dt": "2026-11-01", "risk_level": "MEDIUM", "truth": None},
        {"dt": "2026-11-02", "risk_level": "HIGH", "truth": "volume_burst"},
    ]
    b = dq.app_timeline(dq.connect(dash), "b", "2026-11-01", "2026-11-01")
    assert b["truth"].tolist() == ["foreign_region"]

def test_app_timeline_unknown_app(dash):  # Review Focus 5
    df = dq.app_timeline(dq.connect(dash), "zzz", "2026-11-01", "2026-11-02")
    assert df.empty and "truth" in df.columns

def test_app_subnets_status(dash):  # Review Focus 3: a view do baseline lê a partição vazia de D1
    df = dq.app_subnets(dq.connect(dash), "b", "2026-11-02")
    assert df[["subnet", "baseline_status"]].to_dict("records") == [
        {"subnet": "1.1.1.0/24", "baseline_status": "usual"},
        {"subnet": "5.5.5.0/24", "baseline_status": "nova"},
    ]
```

- [ ] **Step 2:** Rodar. Expected: FAIL com `AttributeError`.
- [ ] **Step 3:** Implementar. O `truth` usa `None` de verdade, e não `NaN`: converta com `.astype(object).where(notna, None)`.
- [ ] **Step 4:** Rodar a suíte inteira com `pytest -q`. Expected: tudo PASS.
- [ ] **Step 5:** Commit: `feat(dashboard): app detail queries`.

### Task 5: App Streamlit

**Files:** Create `dashboard/app.py`.

**Interfaces:**
- Consumes: todas as funções das Tasks 1 a 4.
- `sys.path` recebe `src/`, como em `scripts/simulate.py`.
- `connect` fica em `@st.cache_resource`, com `DATA_DIR` vindo do ambiente e padrão `data`.

- [ ] **Step 1:** Carregar o skill `dataviz` antes de escrever os gráficos, e seguir a paleta e as regras dele.
- [ ] **Step 2:** Implementar:
  - **Checagem de dados:** se `missing_tables` não estiver vazio, mostrar `st.warning` com as tabelas faltando e o comando da Etapa 2b, e depois `st.stop()`.
  - **Lateral:** a data do dia (padrão: a última de `available_dates`) e o período (padrão: todas as datas).
  - **Visão geral:**
    - cinco `st.metric`;
    - gráfico de barras empilhadas de `daily_outcomes`, com as cores "ataque real" e "falso positivo" e os dias sem régua marcados (rótulo ou opacidade);
    - gráfico de `daily_signals`;
    - barras horizontais de `attacks_by_type` (pegos e escapados);
    - duas tabelas de `day_errors`.
  - **IPs suspeitos:** `st.dataframe` de `suspicious_ips` e de `unusual_subnet_scope_errors`.
  - **Detalhe:**
    - um `st.radio` para escolher entre Aplicação e IP;
    - Aplicação: um selectbox alimentado por `app_options`, o gráfico de volume contra esperado com os dias HIGH destacados, a tabela da timeline e `app_subnets` do dia escolhido;
    - IP: um `text_input` já preenchido com o primeiro IP de `suspicious_ips`, seguido da tabela de `ip_activity`;
    - quando um resultado vier vazio, mostrar `st.info("Nenhum dado para esse filtro.")`.
- [ ] **Step 3: Verificar com os dados reais**
  - Rodar `.venv\Scripts\streamlit.exe run dashboard/app.py --server.headless true`, abrir http://localhost:8501 e passar pelas três abas.
  - Expected: nenhum traceback.
  - Expected: em 2026-11-22, os cartões batem com `data/gold/detection_metrics/dt=2026-11-22`.
- [ ] **Step 4: Verificar os critérios de aceite 2 e 3 por script**, com `connect("data")`:
  - a média de precision e recall dos dias com régua pronta deve ser 0,748 e 0,781;
  - a soma de `caught` + `missed` em `attacks_by_type` do período todo deve ser 192.
- [ ] **Step 5:** Verificar a pasta vazia: `DATA_DIR=<pasta vazia>` mostra o aviso e não quebra.
- [ ] **Step 6:** `ruff check .` e `ruff format --check .` passam. Commit: `feat(dashboard): streamlit app with overview, ips and detail tabs`.

### Task 6: Docker e documentação

**Files:**
- Create: `Dockerfile.dashboard`
- Modify: `docker-compose.yaml`, `README.md`, `COMO_COMECAR.md` (fora do git, editado só localmente)

- [ ] **Step 1:** Criar `Dockerfile.dashboard`:
  - base `python:3.12-slim`;
  - `COPY requirements.txt requirements-dashboard.txt` e `pip install -r requirements-dashboard.txt --no-cache-dir`;
  - `ENV PYTHONPATH=/app/src DATA_DIR=/data`;
  - `WORKDIR /app`;
  - `CMD streamlit run dashboard/app.py --server.address 0.0.0.0 --server.port 8501 --server.headless true`.
- [ ] **Step 2:** Adicionar o serviço `dashboard` no compose:
  - `build: {context: ., dockerfile: Dockerfile.dashboard}`;
  - `ports: ["8501:8501"]`;
  - volumes `./data:/data:ro`, `./src:/app/src:ro` e `./dashboard:/app/dashboard:ro`.
- [ ] **Step 3:** Rodar `docker compose up -d --build dashboard` e abrir http://localhost:8501. Expected: as abas carregam com os 30 dias.
- [ ] **Step 4:** Atualizar o README:
  - seção "Dashboard", com como rodar pelo venv e pelo compose e o que cada aba mostra;
  - a linha do dashboard no mermaid, se couber;
  - roadmap com `- [x] Local analytics dashboard (Streamlit + DuckDB)`.
- [ ] **Step 5:** No `COMO_COMECAR.md`, criar a "Etapa 2c: dashboard", em PT-BR, explicando o que é o DuckDB e os dois jeitos de rodar.
- [ ] **Step 6:** Rodar `pytest -q`, `ruff check .`, `ruff format --check .` e `terraform fmt -check`. Commit: `feat(dashboard): compose service and docs`.
