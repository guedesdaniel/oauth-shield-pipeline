# Subnets usuais aprendidas + 30 dias de dados — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** O pipeline aprende, do histórico de 14 dias, as subnets /24 usuais de cada software e detecta erros de scope vindos de subnet não usual. A base sintética ganha 30 dias com cenário difícil (fraude discreta e migrações legítimas), e precisão e recall passam a variar de forma honesta.

**Architecture:** O gerador continua determinístico e sem estado; migrações vêm de um cronograma derivado da semente. A nova silver `client_subnet_daily` (software × subnet × dia) alimenta a task `build_baseline`, que lê as 14 partições anteriores e grava `client_subnet_baseline`. O gold ganha o sinal `s_new_subnet_scope_errors`. Os 30 dias são gerados por backfill do Airflow.

**Tech Stack:** Python 3.11+, pandas, numpy, pyarrow, boto3/botocore, Apache Airflow 3.3.1 (Docker), Terraform (AWS Glue/Athena), pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-11-23-subnet-baseline-30-days-design.md` (leia antes; este plano argumenta a partir dela).

## Global Constraints

- Subnet = /24 IPv4, formato exato `"a.b.c.0/24"`.
- Janela da régua = **14 dias**, D-14 … D-1, **nunca inclui o dia D**.
- Subnet usual = em ordem decrescente de tokens (status 200) na janela, entram as subnets até a que cruza **95%**, inclusive.
- Régua pronta **por dia**: `window_days_available >= 14`. Antes disso, o sinal novo é sempre `False`.
- Sinal novo: `s_new_subnet_scope_errors`, limite `new_subnet_scope_errors_min = 5`, peso **40**, reason exata `"scope errors from a subnet not usual for this app"`. É calculado por par software + subnet, **sem dividir pelo volume total**.
- Sinais, pesos e limites antigos **não mudam**.
- Precisão e recall **nunca** são sorteados nem forçados; só saem de alertas HIGH × `ground_truth`.
- O fraudador usa o mesmo espaço de IPs brasileiros (`177.x.y.z`) dos legítimos e difere só na /24.
- Gerador determinístico: mesmo `(cfg, dt)` → mesmos dados, inclusive migrações.
- Migração move **todo** o tráfego para a subnet nova. O cadastro (`usual_ips`) só muda se a migração foi avisada (50%).
- `STORAGE_BACKEND=local` continua funcionando sem nuvem; o layout `<layer>/<table>/dt=YYYY-MM-DD/part-0000.parquet` é o mesmo no S3.
- Colunas gravadas em Parquet **não** se chamam `dt` (`dt` é a chave de partição no Glue).
- Metas nos dias 15–30: recall médio 0,65–0,80 (pior dia ≥ 0,45) e precisão média 0,55–0,75 (pior dia ≥ 0,35).
- `ruff check .` limpo (line-length 120); `terraform fmt -check` e `terraform validate` limpos.

## Review Focus

1. **Partição faltando no meio da janela** (um dia que falhou): `window_days_available` = 13, régua não pronta e sinal desligado naquele dia, sem erro. Teste em Task 5 e Task 2.
2. **Partição inexistente no S3** (`NoSuchKey`): o `read_many` pula o dia em vez de quebrar a task. Teste em Task 2.
3. **Software sem nenhum evento no dia D** (não aparece em `client_subnet_daily`): o score sai com o sinal novo `False`, sem erro de merge. Teste em Task 6.
4. **Fronteira do limite no dia da migração**: 4 erros de scope na subnet nova não disparam; 5 disparam (falso positivo aceito). Teste em Task 6.
5. **Rotação de host dentro da subnet de casa**: um IP novo na mesma /24 nunca dispara o sinal novo. Teste em Task 6.

---

## Mapa de arquivos

| Arquivo | Responsabilidade |
|---|---|
| `src/oauth_shield/network.py` (novo) | Helpers de IP/subnet: `subnet_of`, `random_br_subnet`, `random_host` |
| `src/oauth_shield/storage.py` | + `read_many` (várias partições, pula as ausentes) |
| `src/oauth_shield/generator.py` | Subnets de casa, rotação, migrações, cadastro por dia, `benign_events`, ataque novo e intensidades |
| `src/oauth_shield/aggregate.py` | + `client_subnet_daily` |
| `src/oauth_shield/baseline.py` (novo) | Janela de 14 dias, regra dos 95%, prontidão |
| `src/oauth_shield/risk.py` | + sinal novo, `detection_metrics` com `baseline_ready` |
| `dags/oauth_shield_daily.py` | Task `build_baseline`, novas gravações, `start_date` |
| `scripts/simulate.py` (novo) | Simulação em memória de N dias para **ajuste** de parâmetros (não substitui o Airflow) |
| `infra/terraform/main.tf`, `sql/athena_queries.sql` | Schemas e queries |
| `README.md`, `COMO_COMECAR.md` | Docs |

---

### Task 0: Branch de trabalho

- [ ] **Step 1:** `git status`. Se houver mudanças não commitadas que não são deste plano, **pare e pergunte ao dono** o que fazer com elas.
- [ ] **Step 2:** `git checkout -b feat/subnet-baseline` → Expected: `Switched to a new branch 'feat/subnet-baseline'`.

---

### Task 1: Helpers de rede

**Files:**
- Create: `src/oauth_shield/network.py`
- Test: `tests/test_network.py`

**Interfaces:**
- Produces:
  - `subnet_of(ip: str) -> str`
  - `random_br_subnet(rng: np.random.Generator) -> str` (sempre `177.x.y.0/24`)
  - `random_host(subnet: str, rng: np.random.Generator) -> str` (host 1–254 dentro da /24)

- [ ] **Step 1: Testes que falham**

```python
from oauth_shield.network import random_br_subnet, random_host, subnet_of
import numpy as np

def test_subnet_of():
    assert subnet_of("177.10.20.33") == "177.10.20.0/24"
    assert subnet_of("45.1.2.254") == "45.1.2.0/24"

def test_random_host_stays_in_subnet():
    rng = np.random.default_rng(1)
    sn = random_br_subnet(rng)
    assert sn.startswith("177.") and sn.endswith(".0/24")
    for _ in range(50):
        h = random_host(sn, rng)
        assert subnet_of(h) == sn
        assert 1 <= int(h.split(".")[3]) <= 254
```

- [ ] **Step 2:** `pytest tests/test_network.py -v` → Expected: FAIL (`ModuleNotFoundError`).
- [ ] **Step 3:** Implemente as 3 funções em `network.py`.
- [ ] **Step 4:** `pytest tests/test_network.py -v` → Expected: PASS.
- [ ] **Step 5:** `git add src/oauth_shield/network.py tests/test_network.py && git commit -m "feat: add IPv4 /24 subnet helpers"`

---

### Task 2: `Storage.read_many`

**Files:**
- Modify: `src/oauth_shield/storage.py`
- Test: `tests/test_storage.py`

**Interfaces:**
- Produces: `Storage.read_many(self, layer: str, table: str, dts: list[str]) -> tuple[pd.DataFrame, int]`. Devolve as partições existentes concatenadas, com uma coluna `dt` adicionada, e quantas partições foram encontradas. Se nenhuma existir, devolve um `DataFrame` vazio e `0`. Local: pula arquivo inexistente. S3: pula `botocore.exceptions.ClientError` com código `NoSuchKey` (ou `404`) e relança qualquer outro erro.

- [ ] **Step 1: Testes que falham**

```python
def test_read_many_skips_missing_local(tmp_path, events):
    store = Storage(backend="local", data_dir=str(tmp_path))
    store.write(events.head(10), "silver", "t", "2026-11-01")
    store.write(events.head(5), "silver", "t", "2026-11-03")
    df, n = store.read_many("silver", "t", ["2026-11-01", "2026-11-02", "2026-11-03"])
    assert n == 2 and len(df) == 15
    assert set(df["dt"]) == {"2026-11-01", "2026-11-03"}

def test_read_many_none_found(tmp_path):
    df, n = Storage(backend="local", data_dir=str(tmp_path)).read_many("silver", "t", ["2026-11-01"])
    assert n == 0 and df.empty

def test_read_many_s3_skips_nosuchkey(monkeypatch):
    from botocore.exceptions import ClientError
    class FakeS3:
        def get_object(self, Bucket, Key):
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
    store = Storage(backend="s3", bucket="b")
    store._s3 = FakeS3()
    df, n = store.read_many("silver", "t", ["2026-11-01"])
    assert n == 0 and df.empty

def test_read_many_s3_reraises_other_errors():
    from botocore.exceptions import ClientError
    class FakeS3:
        def get_object(self, Bucket, Key):
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetObject")
    store = Storage(backend="s3", bucket="b")
    store._s3 = FakeS3()
    with pytest.raises(ClientError):
        store.read_many("silver", "t", ["2026-11-01"])
```

- [ ] **Step 2:** `pytest tests/test_storage.py -v` → Expected: 4 novos FAIL (`AttributeError: read_many`).
- [ ] **Step 3:** Implemente `read_many` reutilizando `read`.
- [ ] **Step 4:** `pytest tests/test_storage.py -v` → Expected: PASS.
- [ ] **Step 5:** `git commit -am "feat: Storage.read_many skips missing partitions"` (inclua o teste).

---

### Task 3: Gerador — subnets de casa, rotação, migrações e cadastro por dia

**Files:**
- Modify: `src/oauth_shield/generator.py`
- Modify: `tests/conftest.py` (o fixture `day` passa a desempacotar 3 valores)
- Test: `tests/test_generator.py`

**Interfaces:**
- Consumes: `network.random_br_subnet`, `network.random_host`, `network.subnet_of`.
- Produces:
  - `GeneratorConfig`: renomear `noise_new_ip_rate` → `noise_ip_rotation_rate: float = 0.02`. Novos campos: `migration_rate_per_day: float = 1 / 600`, `migration_notify_rate: float = 0.5`, `migration_epoch: str = "2026-10-01"`.
  - `build_client_profiles(cfg) -> DataFrame`: colunas atuais + `home_subnets` (str com subnets separadas por espaço). Cada software tem 1–3 subnets de casa; cada subnet, 1–2 hosts em `usual_ips`. Volume: `clip(lognormal(5.2, 1.3), 20, 6000)` (refina a "chamada minha" da spec: o decil superior fica em ~1.000/dia).
  - `BENIGN_COLUMNS = ["client_id", "event_type", "subnet", "notified"]` (`event_type` sempre `"subnet_migration"`).
  - `migrations_until(profiles: DataFrame, dt: str, cfg) -> DataFrame[client_id, migration_date, new_subnet, new_hosts, notified]`: todas as migrações com `migration_epoch <= migration_date <= dt`. Para cada dia desde o epoch, usa `np.random.default_rng([cfg.seed, int(yyyymmdd), 7])`; cada software migra com probabilidade `migration_rate_per_day`, recebe uma nova /24 (diferente das atuais), 1–3 hosts nela e `notified ~ Bernoulli(migration_notify_rate)`.
  - `network_for_day(profiles, dt, cfg) -> DataFrame[client_id, home_subnets, hosts]`: rede **real** do software em `dt`, já com a última migração `<= dt` aplicada (o tráfego todo vai para ela).
  - `registry_for_day(profiles, dt, cfg) -> DataFrame`: mesmas colunas de `profiles`. `usual_ips` e `home_subnets` só refletem a última migração **avisada** `<= dt`. É o que a DAG grava em `bronze/client_profile`.
  - `generate_day(profiles, dt, cfg) -> tuple[events, ground_truth, benign_events]`: o tráfego normal usa `network_for_day`. A rotação (`noise_ip_rotation_rate`) troca para `random_host` numa subnet de casa **atual**. `benign_events` lista as migrações com `migration_date == dt`.

- [ ] **Step 1: Testes que falham** (em `tests/test_generator.py`)

```python
def test_profiles_have_home_subnets(profiles):
    for _, p in profiles.iterrows():
        homes = set(p["home_subnets"].split())
        assert 1 <= len(homes) <= 3
        assert {subnet_of(ip) for ip in p["usual_ips"].split()} <= homes

def test_migrations_are_deterministic_and_bounded(profiles, cfg):
    a = generator.migrations_until(profiles, "2026-11-20", cfg)
    b = generator.migrations_until(profiles, "2026-11-20", cfg)
    pd.testing.assert_frame_equal(a, b)
    assert (a["migration_date"] <= "2026-11-20").all() and (a["migration_date"] >= cfg.migration_epoch).all()
    assert len(a) > 0

def test_migrated_client_traffic_moves_entirely(profiles, cfg):
    mig = generator.migrations_until(profiles, DT, cfg)
    row = mig.sort_values("migration_date").iloc[-1]   # a migração mais recente
    events, _, _ = generator.generate_day(profiles, DT, cfg)
    sub = events[events["client_id"] == row["client_id"]]
    normal = sub[sub["country"] == "BR"]
    # todo tráfego normal do software sai da subnet nova (ataques podem adicionar outras)
    assert (normal["source_ip"].map(subnet_of) == row["new_subnet"]).mean() > 0.9

def test_registry_only_follows_notified_migrations(profiles, cfg):
    mig = generator.migrations_until(profiles, DT, cfg)
    reg = generator.registry_for_day(profiles, DT, cfg).set_index("client_id")
    last = mig.sort_values("migration_date").groupby("client_id").tail(1)
    for _, m in last.iterrows():
        regs = set(reg.loc[m["client_id"], "home_subnets"].split())
        assert (m["new_subnet"] in regs) == bool(m["notified"])

def test_rotation_stays_in_home_subnet(profiles, cfg, events):
    net = generator.network_for_day(profiles, DT, cfg).set_index("client_id")
    normal = events[(events["country"] == "BR") & (events["status_code"] == 200)]
    in_home = normal.apply(lambda r: subnet_of(r["source_ip"]) in net.loc[r["client_id"], "home_subnets"].split(), axis=1)
    assert in_home.mean() > 0.97   # só ataques ficam de fora

def test_benign_events_schema(day):
    assert list(day[2].columns) == generator.BENIGN_COLUMNS
```

Ajuste `test_day_is_deterministic` para comparar também `benign_events`. O fixture `cfg` em `conftest.py` passa a usar `migration_rate_per_day=1/100` (com 120 clientes, garante migrações no `DT` dos testes). O fixture `day` desempacota 3 valores e ganha o fixture `benign_events`.

- [ ] **Step 2:** `pytest tests/test_generator.py -v` → Expected: os novos FAIL.
- [ ] **Step 3:** Implemente as interfaces acima.
- [ ] **Step 4:** `pytest -q` → Expected: `test_generator.py` passa. Outros arquivos podem falhar só por causa da tupla de 3 (corrigidos na Task 6/7); `test_aggregate.py` e `test_storage.py` devem passar.
- [ ] **Step 5:** `git commit -am "feat(generator): home subnets, in-subnet rotation, deterministic migrations"` (inclua os arquivos novos).

---

### Task 4: Gerador — ataque `new_subnet_probing` e intensidades que cruzam limites

**Files:**
- Modify: `src/oauth_shield/generator.py`
- Test: `tests/test_generator.py`

**Interfaces:**
- Produces: `ATTACK_TYPES = ["scope_probing", "credential_stuffing", "geo_anomaly", "volume_burst", "new_subnet_probing"]` (o novo no fim, para manter o rodízio dos antigos). `GeneratorConfig.new_subnet_victim_quantile: float = 0.9`.

Valores iniciais (a Task 10 pode ajustar; as faixas ficam em constantes nomeadas no topo do módulo):

| Ataque | Hoje | Novo |
|---|---|---|
| `scope_probing` | 40–120 erros | 5–60 |
| `credential_stuffing` | 30–80 hits na vítima, 15 outros | 10–60 hits, 6–15 outros |
| `geo_anomaly` | 30–100 pedidos | 2–40 |
| `volume_burst` | 5–8× | 2–6× |
| `new_subnet_probing` | — | 8–40 pedidos, fração de `invalid_scope` ~ U(0,60; 0,85), o resto 200 em scope concedido |

- `new_subnet_probing`: as vítimas vêm do decil superior de `expected_daily_volume` (`new_subnet_victim_quantile`). O IP é `random_host(random_br_subnet(rng))`, com a /24 diferente de todas as subnets de casa atuais da vítima. Todo o tráfego do ataque sai de **um** IP.
- Seleção de vítimas: mantenha `n_attacked` e o rodízio `i % len(ATTACK_TYPES)`. Para os slots `new_subnet_probing`, sorteie entre o decil superior ainda não escolhido.

- [ ] **Step 1: Testes que falham**

```python
def test_every_attack_type_is_injected(ground_truth):   # já existe; passa a exigir os 5 tipos
    assert set(ground_truth["attack_type"]) == set(generator.ATTACK_TYPES)

def test_new_subnet_probing_shape(profiles, cfg, events, ground_truth):
    net = generator.network_for_day(profiles, DT, cfg).set_index("client_id")
    q = profiles["expected_daily_volume"].quantile(cfg.new_subnet_victim_quantile)
    for cid in ground_truth.loc[ground_truth["attack_type"] == "new_subnet_probing", "client_id"]:
        assert profiles.set_index("client_id").loc[cid, "expected_daily_volume"] >= q
        homes = set(net.loc[cid, "home_subnets"].split())
        foreign_sn = events[(events["client_id"] == cid) & ~events["source_ip"].map(subnet_of).isin(homes)
                            & (events["country"] == "BR")]
        assert 8 <= len(foreign_sn) <= 40
        assert foreign_sn["source_ip"].nunique() == 1
        assert foreign_sn["source_ip"].iloc[0].startswith("177.")
        assert (foreign_sn["status_code"] == 400).mean() >= 0.5
```

(Atenção: o filtro por subnet não usual também pega a rotação, que fica sempre em casa, e migrações, que mudam as `home_subnets` atuais. Por isso compare contra `network_for_day`.)

- [ ] **Step 2:** `pytest tests/test_generator.py -v` → Expected: os novos FAIL.
- [ ] **Step 3:** Implemente o ataque e as faixas novas.
- [ ] **Step 4:** `pytest tests/test_generator.py -v` → Expected: PASS.
- [ ] **Step 5:** `git commit -am "feat(generator): new_subnet_probing attack and threshold-crossing intensities"`

---

### Task 5: Silver `client_subnet_daily` e régua `client_subnet_baseline`

**Files:**
- Modify: `src/oauth_shield/aggregate.py`
- Create: `src/oauth_shield/baseline.py`
- Test: `tests/test_aggregate.py`, `tests/test_baseline.py` (novo)

**Interfaces:**
- Consumes: `network.subnet_of`.
- Produces:
  - `aggregate.CLIENT_SUBNET_DAILY_COLUMNS = ["client_id", "subnet", "total_requests", "success_count", "invalid_scope_count", "distinct_ips"]`
  - `aggregate.client_subnet_daily(events: DataFrame) -> DataFrame` (todas as contagens `int64`)
  - `baseline.BaselineConfig(window_days: int = 14, coverage: float = 0.95, min_days: int = 14)` (frozen dataclass)
  - `baseline.BASELINE_COLUMNS = ["client_id", "subnet", "window_tokens", "token_share", "days_seen", "is_usual", "window_days_available"]`
  - `baseline.window_dates(dt: str, days: int = 14) -> list[str]`: D-14 … D-1, em ordem crescente.
  - `baseline.build_baseline(history: DataFrame, window_days_available: int) -> DataFrame`. `history` é a saída de `read_many` (colunas de `client_subnet_daily` + `dt`). Devolve `BASELINE_COLUMNS`, com dtypes corretos mesmo vazio.
  - `baseline.is_ready(window_days_available: int, cfg: BaselineConfig = BaselineConfig()) -> bool`

Regra do `is_usual` (por `client_id`, só subnets com `window_tokens > 0`): ordene por `window_tokens` decrescente, `cum = token_share.cumsum()`, e `is_usual = (cum - token_share) < coverage`. Isso inclui a subnet que cruza 95%.

- [ ] **Step 1: Testes que falham**

```python
# tests/test_aggregate.py
def test_client_subnet_daily_reconciles(events):
    sd = aggregate.client_subnet_daily(events)
    assert list(sd.columns) == aggregate.CLIENT_SUBNET_DAILY_COLUMNS
    assert sd["total_requests"].sum() == len(events)
    assert sd["subnet"].str.endswith(".0/24").all()
    assert not sd.duplicated(["client_id", "subnet"]).any()

# tests/test_baseline.py
def test_window_excludes_today():
    w = baseline.window_dates("2026-11-15")
    assert w[0] == "2026-11-01" and w[-1] == "2026-11-14" and len(w) == 14

def _hist(rows):  # rows: (dt, client, subnet, success)
    return pd.DataFrame([{"dt": d, "client_id": c, "subnet": s, "total_requests": n, "success_count": n,
                          "invalid_scope_count": 0, "distinct_ips": 1} for d, c, s, n in rows])

def test_95_percent_rule_includes_crossing_subnet():
    h = _hist([("2026-11-01", "a", "1.1.1.0/24", 900), ("2026-11-01", "a", "2.2.2.0/24", 80),
               ("2026-11-01", "a", "3.3.3.0/24", 20)])
    b = baseline.build_baseline(h, 14).set_index("subnet")
    assert b.loc["1.1.1.0/24", "is_usual"] and b.loc["2.2.2.0/24", "is_usual"]   # 0,90 → cruza com 0,98
    assert not b.loc["3.3.3.0/24", "is_usual"]

def test_days_seen_and_share():
    h = _hist([("2026-11-01", "a", "1.1.1.0/24", 50), ("2026-11-02", "a", "1.1.1.0/24", 50)])
    b = baseline.build_baseline(h, 14).iloc[0]
    assert b["days_seen"] == 2 and b["window_tokens"] == 100 and b["token_share"] == 1.0

def test_empty_history_has_schema():
    b = baseline.build_baseline(pd.DataFrame(), 0)
    assert list(b.columns) == baseline.BASELINE_COLUMNS and b.empty

def test_readiness_is_per_day():
    assert not baseline.is_ready(13)      # um dia da janela faltando (Review Focus 1)
    assert baseline.is_ready(14)
```

- [ ] **Step 2:** `pytest tests/test_aggregate.py tests/test_baseline.py -v` → Expected: FAIL.
- [ ] **Step 3:** Implemente.
- [ ] **Step 4:** Mesmo comando → Expected: PASS.
- [ ] **Step 5:** `git add ... && git commit -m "feat: client_subnet_daily silver and 14-day learned subnet baseline"`

---

### Task 6: Gold — sinal `s_new_subnet_scope_errors`

**Files:**
- Modify: `src/oauth_shield/risk.py`
- Test: `tests/test_risk.py`

**Interfaces:**
- Consumes: `aggregate.CLIENT_SUBNET_DAILY_COLUMNS`, `baseline.BASELINE_COLUMNS`.
- Produces:
  - `Thresholds.new_subnet_scope_errors_min: int = 5`; `WEIGHTS["s_new_subnet_scope_errors"] = 40`; `REASONS["s_new_subnet_scope_errors"] = "scope errors from a subnet not usual for this app"`. `RISK_COLUMNS` ganha a coluna no fim.
  - `score_clients(client_daily, ip_daily, events, subnet_daily: DataFrame | None = None, baseline: DataFrame | None = None, baseline_ready: bool = False, t: Thresholds = Thresholds()) -> DataFrame`. Se `baseline_ready` for `False` ou `subnet_daily` for `None`, o sinal é `False` para todos. Uma subnet ausente da régua conta como não usual.
  - `DETECTION_COLUMNS = ["run_date", "flagged", "true_positives", "false_positives", "false_negatives", "precision", "recall", "baseline_ready"]`; `detection_metrics(scores, ground_truth, dt, baseline_ready: bool = False)`.

- [ ] **Step 1: Testes que falham** (helpers montam frames mínimos; o software `"a"` tem a subnet usual `1.1.1.0/24`)

```python
def _score(subnet_rows, ready=True, extra_clients=()):
    # subnet_rows: (client, subnet, invalid_scope_count); client_daily "quieto" para "a" e extra_clients
    ...  # monta client_daily (como test_quiet_client_scores_zero), ip_daily vazio, events vazio,
         # baseline com ("a", "1.1.1.0/24", is_usual=True)
    return risk.score_clients(cd, ips, ev, subnet_daily=sd, baseline=bl, baseline_ready=ready).set_index("client_id")

def test_fires_on_unusual_subnet_at_threshold():          # Review Focus 4
    assert _score([("a", "9.9.9.0/24", 5)]).loc["a", "s_new_subnet_scope_errors"]
    assert not _score([("a", "9.9.9.0/24", 4)]).loc["a", "s_new_subnet_scope_errors"]

def test_alone_is_high_with_reason():
    r = _score([("a", "9.9.9.0/24", 5)]).loc["a"]
    assert r["risk_level"] == "HIGH" and "scope errors from a subnet not usual" in r["reasons"]

def test_usual_subnet_never_fires():                       # Review Focus 5 (rotação na mesma /24)
    assert not _score([("a", "1.1.1.0/24", 50)]).loc["a", "s_new_subnet_scope_errors"]

def test_not_diluted_by_client_volume():
    # cliente com 100.000 pedidos: 5 erros = 0,005%, e mesmo assim dispara
    ...

def test_off_when_baseline_not_ready():
    assert not _score([("a", "9.9.9.0/24", 50)], ready=False).loc["a", "s_new_subnet_scope_errors"]

def test_client_without_events_today():                    # Review Focus 3
    r = _score([("a", "9.9.9.0/24", 5)], extra_clients=["b"])
    assert not r.loc["b", "s_new_subnet_scope_errors"] and r.loc["b", "risk_score"] == 0

def test_detection_metrics_carries_baseline_ready(scores, ground_truth):
    m = risk.detection_metrics(scores, ground_truth, DT, baseline_ready=True)
    assert list(m.columns) == risk.DETECTION_COLUMNS and bool(m.iloc[0]["baseline_ready"])
```

Também:
- **Remova** `test_detects_injected_attacks` e `test_each_attack_triggers_its_signal`. Com intensidades que cruzam os limites, eles deixam de ser verdade por design. As metas agora são verificadas pela simulação da Task 10.
- **Substitua** por `test_metrics_reconcile(scores, ground_truth)`: `tp + fn == len(ground_truth)`, `tp + fp == flagged` e precisão/recall em [0, 1].

- [ ] **Step 2:** `pytest tests/test_risk.py -v` → Expected: os novos FAIL.
- [ ] **Step 3:** Implemente.
- [ ] **Step 4:** `pytest -q && ruff check .` → Expected: tudo PASS, ruff limpo.
- [ ] **Step 5:** `git commit -am "feat(risk): s_new_subnet_scope_errors signal from learned baseline"`

---

### Task 7: DAG

**Files:**
- Modify: `dags/oauth_shield_daily.py`

**Interfaces:**
- Consumes: `generator.registry_for_day`, `generate_day` (tupla de 3), `aggregate.client_subnet_daily`, `baseline.window_dates/build_baseline/is_ready`, `Storage.read_many`, `risk.score_clients(..., subnet_daily, baseline, baseline_ready)`, `detection_metrics(..., baseline_ready)`.

O que muda:
- `start_date = pendulum.datetime(2026, 10, 1, tz="UTC")`. `catchup=False` e `max_active_runs=1` continuam.
- `generate_events` grava `bronze/client_profile` = `registry_for_day(profiles, dt, cfg)` e grava também `bronze/benign_events`.
- `build_silver` grava também `silver/client_subnet_daily`.
- Task nova `build_baseline(dt)`: `history, n = store.read_many("silver", "client_subnet_daily", window_dates(dt))`, grava `silver/client_subnet_baseline` com `build_baseline(history, n)` e loga `n` e `is_ready(n)`.
- `score_risk` lê `client_subnet_daily` e `client_subnet_baseline` do dia. `baseline_ready = is_ready(baseline["window_days_available"].max() if not empty else 0)`.
- Encadeamento: `score_risk(build_baseline(build_silver(check_quality(generate_events()))))`.

- [ ] **Step 1:** Edite a DAG.
- [ ] **Step 2:** `ruff check dags` → Expected: limpo.
- [ ] **Step 3:** Com o Docker Desktop aberto: `docker compose up -d --force-recreate airflow` e depois `docker compose exec -T airflow airflow dags list-import-errors` → Expected: `No data found`.
- [ ] **Step 4:** `docker compose exec -T airflow airflow dags test oauth_shield_daily 2026-11-22` → Expected: as 5 tasks em `success`; o log de `build_baseline` mostra `n=0`, não pronta. Apague `./data/*/*/dt=2026-11-22` depois (ou deixe para a limpeza da Task 10).
- [ ] **Step 5:** `git commit -am "feat(dag): build_baseline task and new silver/bronze outputs"`

---

### Task 8: Terraform e SQL

**Files:**
- Modify: `infra/terraform/main.tf` (`locals.tables`), `sql/athena_queries.sql`

- [ ] **Step 1:** Em `locals.tables`, adicione os itens abaixo, seguindo o tipo do Parquet (`int64` → `bigint`, `bool` → `boolean`, `float` → `double`):
  - `client_subnet_daily` (prefixo `silver/client_subnet_daily`);
  - `client_subnet_baseline` (`silver/client_subnet_baseline`);
  - `ground_truth` (`bronze/ground_truth`: `client_id`, `attack_type`);
  - `benign_events` (`bronze/benign_events`: `client_id`, `event_type`, `subnet` string, `notified` boolean);
  - `s_new_subnet_scope_errors boolean` em `risk_scores` e `baseline_ready boolean` em `detection_metrics`.
- [ ] **Step 2:** Em `athena_queries.sql`:
  - troque `current_date` por uma data literal com um comentário avisando que `dt` é UTC;
  - adicione a query 5, "subnets não usuais com erro de scope no dia": `client_subnet_daily` LEFT JOIN `client_subnet_baseline` no mesmo `dt`, `COALESCE(is_usual, false) = false AND invalid_scope_count >= 5`.
- [ ] **Step 3:** `cd infra/terraform && terraform fmt -check && terraform validate` → Expected: sem saída do fmt e `Success! The configuration is valid.`
- [ ] **Step 4:** `git commit -am "chore(infra): Glue tables for subnet baseline, ground truth and benign events"`

---

### Task 9: Simulação para ajuste

**Files:**
- Create: `scripts/simulate.py`

**Interfaces:**
- CLI: `python scripts/simulate.py --end 2026-11-22 --days 30`. Roda em memória, para cada dia em ordem: `generate_day` → `client_daily`/`ip_daily`/`client_subnet_daily` → `build_baseline` (com os 14 dias anteriores já calculados) → `score_clients` → `detection_metrics`. Imprime uma tabela por dia e, para os dias com `baseline_ready`, a média e o mínimo de precisão e recall, o recall por `attack_type` e quantos FPs vieram de softwares que migraram no dia (`benign_events`).
- Não grava nada em disco. Só existe para ajustar parâmetros rápido; os dados oficiais vêm do backfill.

- [ ] **Step 1:** Implemente, reutilizando as funções de `src/` (zero lógica de negócio duplicada).
- [ ] **Step 2:** `python scripts/simulate.py --end 2026-11-22 --days 30` → Expected: 30 linhas, 16 com `baseline_ready=True`, e o resumo.
- [ ] **Step 3:** `git add scripts/simulate.py && git commit -m "chore: offline simulation script for parameter tuning"`

---

### Task 10: Ajuste para as metas, backfill de 30 dias e docs

**Files:**
- Modify: `src/oauth_shield/generator.py` (só as constantes de faixa, se precisar), `COMO_COMECAR.md`, `README.md`

- [ ] **Step 1:** Rode a simulação. Se as médias ou os mínimos dos dias 15–30 saírem das metas (Global Constraints), ajuste **só as faixas do gerador** (Task 4), `migration_rate_per_day` ou `new_subnet_victim_quantile`. Nunca mexa em regras, pesos ou limites antigos. Repita até cair na faixa. Confirme também que há **≥ 1 FP explicado por `benign_events`** e **≥ 1 FN de `new_subnet_probing`**. Rode `pytest -q` depois de cada ajuste.
- [ ] **Step 2:** `git commit -am "tune: generator ranges to hit hard-scenario targets"` (se mudou algo).
- [ ] **Step 3:** Limpe os dados antigos: `Remove-Item -Recurse -Force data\bronze, data\silver, data\gold`. Confirme `STORAGE_BACKEND=local` no `.env`.
- [ ] **Step 4:** `docker compose exec -T airflow airflow backfill create --help`. Confirme as flags na versão da imagem e anote o comando no `COMO_COMECAR.md`. Esperado: algo como `airflow backfill create --dag-id oauth_shield_daily --from-date 2026-10-24 --to-date 2026-11-22 --max-active-runs 1` (30 dias terminando no dia anterior; ordem crescente).
- [ ] **Step 5:** Rode o backfill. Acompanhe com `airflow dags list-runs oauth_shield_daily -o plain` até 30 runs em `success` (~15–30 min).
- [ ] **Step 6:** Verifique: `data/gold/detection_metrics` tem 30 partições, e os valores dos dias com `baseline_ready=True` batem com a simulação (mesmos números, já que o gerador é determinístico).
- [ ] **Step 7:** Docs:
  - `COMO_COMECAR.md` (PT-BR): seção "Etapa 2b: 30 dias com backfill", explicando o que é backfill, por que precisa ser em ordem (a régua lê os 14 dias anteriores) e como acompanhar na UI.
  - `README.md` (EN): tabela de camadas (+ `client_subnet_daily`, `client_subnet_baseline`, `benign_events`), tabela de sinais (+ `s_new_subnet_scope_errors`, peso 40), detection signals e o parágrafo "Current results" com as médias e mínimos reais dos 16 dias.
- [ ] **Step 8:** `pytest -q && ruff check . && (cd infra/terraform && terraform fmt -check && terraform validate)` → Expected: tudo verde.
- [ ] **Step 9:** `git commit -am "docs: backfill guide and updated results"`
