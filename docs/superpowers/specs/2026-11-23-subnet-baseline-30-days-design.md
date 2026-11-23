# Spec: subnets usuais aprendidas + 30 dias de dados

Data: 2026-11-23 · Status: rascunho para aprovação · Frente 1 de 2 (a frente 2, dashboard, terá spec própria e depende desta)

## 1. Por quê

Hoje precisão e recall dão quase sempre 1,0, porque os ataques sintéticos são escandalosos e o pipeline só tem 1 ou 2 dias de dados. Assim, nem a avaliação nem um futuro dashboard mostram trade-offs reais.

O dono do projeto trabalha com OAuth em Open Finance e trouxe um padrão real que as regras atuais **não pegam**:

> Um software de **muito volume** emite tokens normalmente pelo IP de sempre. Num dia, aparece **um IP de outra subnet**, com **poucos pedidos**: alguns tokens emitidos e vários erros de scope. Ele não volta nos dias seguintes (provável fraudador).

As regras atuais olham o cliente inteiro, e os sinais se diluem no volume. Por exemplo, o `sw-00153` no dia 2026-11-22 teve 49 erros de scope, mas eles eram só 3,1% do tráfego, então nenhum alerta disparou.

Segunda observação do dono: **troca legítima de IP quase sempre acontece dentro da mesma subnet**, por causa da rotação na nuvem. Comparar IP exato gera alarme falso; comparar subnet, não.

**Objetivo:** o pipeline passa a **aprender**, do próprio histórico, quais subnets são usuais para cada software. Com isso ele detecta o padrão acima. A base sintética passa a ter 30 dias, com cenários que fazem precisão e recall **variarem de dia para dia de forma honesta**.

## 2. Objetivos, não-objetivos e anti-objetivos

**Objetivos**
- Gerar 30 dias consecutivos de dados pelo próprio Airflow (backfill).
- Novo cenário de fraude: IP de subnet nova, num dia só, com poucos pedidos e erros de scope, em softwares de alto volume.
- Novo cenário legítimo que gera falso positivo de forma realista: um software migra de subnet de verdade.
- Rotação de IP do dia a dia **dentro da mesma subnet**, para não gerar alarme falso.
- Régua aprendida: subnets usuais por software, numa janela móvel de 14 dias.
- Novo sinal de risco, explicável, baseado nessa régua.
- Dias 15 a 30 avaliados com a régua completa; dias 1 a 14 são aquecimento.
- **Cenário difícil** (decisão do dono): precisão e recall bem abaixo de 1,0, com dias bons e dias ruins. Para chegar lá, os 4 ataques atuais também ganham intensidades que cruzam os limites das regras (*chamada minha*, ver 5.1).

**Não-objetivos** (ficam para depois)
- Dashboard (frente 2).
- Detecção de hora em hora ou streaming (item Kafka/D0 do roadmap).
- Mudar as regras, pesos ou limites dos 4 sinais antigos. O cenário fica mais difícil pelo lado dos **dados**, não por regras piores.
- IPv6, Isolation Forest e ML em geral.
- Subir ou alterar a infraestrutura AWS agora. Ela foi destruída; o Terraform só precisa continuar válido e coerente com os novos schemas.

**Anti-objetivos** (falhas mesmo que "funcione")
- **Nunca** sortear ou forçar precisão e recall. Eles têm de sair da comparação entre os alertas e o `ground_truth`.
- O fraudador não pode ser detectável por um atalho artificial do gerador, como um prefixo de IP exclusivo de atacante. Ele usa o mesmo espaço de IPs brasileiros dos clientes legítimos e só difere na subnet.
- Quebrar a execução local sem nuvem (`STORAGE_BACKEND=local`) ou o mesmo layout de partições no S3.
- Exigir 14 dias de espera para detectar uma fraude. A régua vem do passado; a fraude do dia D é detectada no próprio dia D.

## 3. Decisões tomadas com o dono

| Tema | Decisão |
|---|---|
| Granularidade | **Subnet /24** (os 3 primeiros octetos do IPv4) |
| O que é subnet usual | As subnets que, **juntas, cobrem 95% dos tokens emitidos** (status 200) do software na janela. Em ordem decrescente de tokens, entram até a que cruza 95%, inclusive. Isso generaliza a ideia do dono ("o IP que mais gerou token") para softwares com vários servidores. |
| Janela | **14 dias móveis**: para o dia D, usa D-14 … D-1 (nunca o próprio D) |
| Volume de dados | **30 dias**; dias 1–14 aquecem a régua, **dias 15–30 são avaliados** (16 dias) |
| Onde calcular a régua | **Silver diária pequena + janela por cima**: `client_subnet_daily` por dia; a task `build_baseline` lê as 14 partições anteriores (não relê o bronze) |
| Como gerar os 30 dias | **Backfill do Airflow**, em ordem cronológica, um run por vez |
| Fraudador | Aparece **um dia** e some |
| Dificuldade | **Cenário difícil** (metas na seção 6) |
| Princípio de ajuste | "É melhor ter um falso positivo do que afrouxar": na dúvida, priorizar recall sobre precisão |
| Migração legítima | O software move **todo** o tráfego para a subnet nova (mais falso positivo no dia, aceito pelo princípio acima) |
| Cadastro declarado (`usual_ips`) | Só muda **quando o cliente avisa**. A régua aprendida se atualiza sozinha pelos 14 dias. O dono comenta que o trabalho real dele ainda não tem nenhum dos dois. |

## 4. Abordagens consideradas

**Régua (subnets usuais)**
1. *Escolhida:* silver diária `client_subnet_daily` (software × subnet × dia), com janela de 14 partições por cima. É o padrão medallion (silver alimenta silver), barato no S3 e tolera dia faltando.
2. Recalcular a partir do bronze bruto dos 14 dias. É mais simples, mas relê ~1,2 milhão de eventos por run, 14 vezes mais caro.
3. Estado incremental (régua de ontem + hoje − dia que saiu). É eficiente, porém complexo e propaga erro para sempre. Exagero para 300 clientes.

**Gerar 30 dias**
1. *Escolhida:* backfill do Airflow. É prática real de engenharia de dados, aparece na UI e respeita a ordem.
2. Script Python em loop. É mais rápido, mas duplica a orquestração e fica invisível no Airflow.

## 5. Desenho

### 5.1 Gerador (`src/oauth_shield/generator.py`)

O gerador continua **determinístico e sem estado**: cada dia depende só de `(cfg, profiles, dt)`. Qualquer evento que dure vários dias, como a migração, é derivado deterministicamente da semente, não de dias anteriores.

**Perfis**
- Cada software ganha de 1 a 3 **subnets de casa** (/24) e um pool de IPs dentro delas. Os IPs continuam no espaço brasileiro atual, gerado por `_br_ip`.
- `usual_ips` continua existindo no `client_profile`. Ele passa a ser o "cadastro declarado" (IPs no momento do registro) e segue alimentando o sinal antigo `s_off_baseline_ip`.
- Distribuição de volume: o dono quer "clientes com muita volumetria". Deve haver uma cauda de softwares grandes, de milhares de pedidos por dia. *Chamada minha:* manter a lognormal atual, ajustando-a se for preciso para que o quartil superior tenha volume suficiente para diluir erros (≥ ~1.000/dia).

**Tráfego normal**
- O ruído "IP novo" (`noise_new_ip_rate`) passa a ser **rotação dentro de uma subnet de casa**: um host novo na mesma /24. *Chamada minha:* renomear para `noise_ip_rotation_rate`.
- As demais taxas de ruído (erro de scope, `invalid_client`, rate limit) ficam como estão.

**Novo ataque: `new_subnet_probing`** (entra em `ATTACK_TYPES` e no `ground_truth`)
- Vítimas: só softwares de **alto volume** (*chamada minha:* quartil superior de `expected_daily_volume`).
- Um IP brasileiro de uma **/24 que não é de casa** da vítima, só naquele dia.
- Poucos pedidos: *chamada minha:* entre 8 e 40 no dia, com 60–85% de `invalid_scope` (scopes não concedidos) e o restante 200 em scopes concedidos.
- Os valores são propositalmente próximos do limite do novo sinal, para que alguns casos escapem (falsos negativos honestos).

**Novo evento legítimo: migração de subnet** (não é ataque e não entra no `ground_truth`)
- Um cronograma determinístico, derivado da semente, define quais softwares migram, em que data e para qual nova /24. A partir da data, **todo** o tráfego daquele software sai da subnet nova (decisão do dono), com pool de IPs novo dentro dela. *Chamada minha:* cerca de 1 migração a cada 2 dias no universo de 300 softwares.
- **Aviso ao cadastro:** só uma parte das migrações vem com aviso do cliente. *Chamada minha:* 50%. Quando há aviso, o `client_profile` a partir daquela data traz os IPs novos em `usual_ips`. Sem aviso, o cadastro fica desatualizado e o sinal antigo `s_off_baseline_ip` (+25, MEDIUM) dispara todo dia depois da migração. É a história "cadastro desatualizado gera ruído, a régua aprendida se corrige sozinha", que o dashboard vai mostrar. Para isso, o `client_profile` passa a depender da data (`build_client_profiles(cfg, dt)` ou equivalente) e continua determinístico.
- No dia da migração, o ruído normal de erro de scope (0,5%) de um software grande cai inteiro na subnet "nova". Pode disparar o sinal novo, o que é um **falso positivo realista**. Nos dias seguintes, a subnet entra na régua conforme acumula tokens.
- Para explicar falsos positivos no dashboard, o gerador grava uma tabela bronze `benign_events` (`client_id`, `event_type="subnet_migration"`, `subnet`, `dt`), que só serve para análise, como o `ground_truth`.

**Ataques atuais:** a mecânica dos 4 tipos continua, mas as **intensidades passam a cruzar os limites** das regras, para que parte dos casos escape (*chamada minha*, para cumprir o "cenário difícil"). Exemplos:
- `scope_probing`: hoje gera 40–120 erros, sempre acima do limite de 10. Passa a ir de poucos a muitos erros, e às vezes fica abaixo de 10 ou abaixo de 5% num cliente grande.
- `geo_anomaly`: hoje gera 30–100 pedidos. Passa a incluir casos com menos de 5 pedidos do exterior.
- `volume_burst`: hoje é 5–8× o volume. Passa a incluir picos de 2–3×, abaixo do limite de 3×.
- `credential_stuffing`: também espalha por menos clientes em parte dos dias.

As faixas exatas ficam com o builder (seção 7), com a meta da seção 6 como guia. O total de vítimas por dia continua `max(len(ATTACK_TYPES), round(n_clients * attack_rate))`, distribuído em rodízio pelos 5 tipos.

### 5.2 Silver (`src/oauth_shield/aggregate.py`)

Nova função `subnet_of(ip) -> str`, que retorna `"a.b.c.0/24"`.

**Nova tabela `silver/client_subnet_daily`** (partição `dt`):

| coluna | tipo | significado |
|---|---|---|
| client_id | string | |
| subnet | string | /24 |
| total_requests | bigint | |
| success_count | bigint | tokens emitidos (200) |
| invalid_scope_count | bigint | |
| distinct_ips | bigint | |

**Nova tabela `silver/client_subnet_baseline`** (partição `dt` = o dia **avaliado**, calculada a partir de D-14…D-1):

| coluna | tipo | significado |
|---|---|---|
| client_id | string | |
| subnet | string | |
| window_tokens | bigint | tokens dessa subnet na janela |
| token_share | double | fração dos tokens do software na janela |
| days_seen | bigint | em quantos dias da janela a subnet emitiu token |
| is_usual | boolean | entra no conjunto que cobre 95% |
| window_days_available | bigint | quantas das 14 partições existiam |

- Software sem nenhum token na janela não tem linha. Para ele, nenhuma subnet é usual, e o sinal novo **pode** disparar se houver erros de scope (*chamada minha*: app sem histórico e com erros de scope é suspeito).
- `days_seen` não entra na regra hoje. Fica registrado para análise e para um futuro critério anti-envenenamento.

**Régua pronta** é decidida **por dia**, não por software (*chamada minha*): só quando `window_days_available >= baseline_min_days`, com padrão 14, configurável. Antes disso, o sinal novo fica sempre falso naquele dia, e o `detection_metrics` marca o dia como aquecimento.

### 5.3 Gold (`src/oauth_shield/risk.py`)

**Novo sinal `s_new_subnet_scope_errors`**
- Dispara para o software se, **no dia D**, existir alguma subnet com `is_usual = false` (ou ausente da régua) que tenha `invalid_scope_count >= new_subnet_scope_errors_min`.
- O cálculo é por par software + subnet, **sem dividir pelo volume total** do software. Esse é o ponto central do pedido.
- *Chamada minha:* `new_subnet_scope_errors_min = 5` (em `Thresholds`) e peso **40** (sozinho já dá HIGH, como o dono quer).
- Texto de reason: `"scope errors from a subnet not usual for this app"`.
- Só avalia se a régua estiver pronta.

`RISK_COLUMNS` ganha a coluna `s_new_subnet_scope_errors`. Os sinais e pesos antigos não mudam.

**`detection_metrics`** ganha a coluna `baseline_ready` (boolean). A forma de calcular precisão e recall continua a mesma.

### 5.4 Storage (`src/oauth_shield/storage.py`)

É preciso ler várias partições, aceitando que algumas não existam (início do histórico, dia faltando): por exemplo, `read_many(layer, table, dts) -> DataFrame`, que concatena as existentes e devolve uma coluna `dt`. Isso precisa funcionar igual no local e no S3. A forma exata fica com o builder.

### 5.5 DAG (`dags/oauth_shield_daily.py`)

```
generate_events → check_quality → build_silver → build_baseline → score_risk
```

- `generate_events` passa a gravar também `bronze/benign_events`.
- `build_silver` passa a gravar também `client_subnet_daily`.
- `build_baseline` é nova: lê `client_subnet_daily` de D-14…D-1 e grava `client_subnet_baseline` de D.
- `score_risk` passa a ler a régua do dia.
- `start_date` recua para cobrir o backfill (por exemplo, 2026-10-01). `catchup=False` e `max_active_runs=1` continuam: ativar a DAG não dispara 30 runs sozinha.
- Continua idempotente: rodar o mesmo dia de novo sobrescreve as mesmas partições.

### 5.6 Backfill dos 30 dias

- **30 dias consecutivos terminando no dia anterior ao backfill**, em ordem crescente e um run por vez. O dia D precisa que D-14…D-1 já existam.
- Antes do backfill, apagar o conteúdo de `./data`. As partições atuais (2026-11-22 e 2026-11-23) vêm do gerador antigo.
- O comando exato do backfill no Airflow 3 vai documentado no `COMO_COMECAR.md`, com uma explicação curta do que é backfill (o dono está aprendendo Airflow).
- Tempo esperado: cerca de 15 minutos (~25 s por dia).

### 5.7 Terraform, SQL e docs

- `infra/terraform/main.tf`: em `locals.tables`, adicionar `client_subnet_daily`, `client_subnet_baseline`, `ground_truth` e `benign_events` (*chamada minha*: o Athena fica com as mesmas tabelas que o dashboard vai usar), mais a coluna nova em `risk_scores` e `detection_metrics`. Deve passar `terraform fmt -check` e `terraform validate`. Não é preciso aplicar.
- `sql/athena_queries.sql`: uma query nova com "subnets novas com erro de scope no dia", e trocar `current_date` por uma data explícita ou parametrizada nos comentários. O dt é em UTC (problema visto na prática).
- `README.md` (em inglês): atualizar as tabelas de camadas e sinais e o parágrafo "Current results" com os números reais depois do backfill (precisão e recall agora variam).
- `COMO_COMECAR.md` (em português): seção de backfill.

## 6. Critérios de pronto

- `pytest -q` e `ruff check .` verdes, mais `terraform fmt -check` e `terraform validate`.
- Testes novos cobrindo no mínimo:
  - `subnet_of`;
  - a regra dos 95% (incluindo a subnet que cruza o limite);
  - janela sem o próprio dia D;
  - régua não pronta antes de 14 dias;
  - sinal dispara para o fraudador e **não** dispara para a rotação dentro da subnet;
  - o gerador continua determinístico, com migração e fraude incluídas.
- Os testes atuais que assumem "todo ataque dispara seu sinal num dia isolado" precisam ser adaptados, porque o `new_subnet_probing` depende de histórico.
- Backfill de 30 dias executado localmente, com todas as runs em sucesso.
- **Metas do cenário difícil** nos dias 15–30 (*proposta minha*, com o recall priorizado pelo princípio do dono):

  | | Média dos 16 dias | Pior dia |
  |---|---|---|
  | Recall | 0,65 – 0,80 | ≥ 0,45 |
  | Precisão | 0,55 – 0,75 | ≥ 0,35 |

  Acima da faixa, o cenário ficou fácil demais; abaixo, o sistema parece quebrado. Os parâmetros de 5.1 são ajustados até cair na faixa, e esse ajuste fica com o builder.
- Ao menos um falso positivo explicável por `benign_events` e ao menos um falso negativo de `new_subnet_probing` aparecem nos 16 dias avaliados.

## 7. O que fica com o builder

- Os números exatos marcados como *chamada minha*: faixas do fraudador, frequência de migração, limite do sinal e eventual ajuste da lognormal. O alvo é o critério de pronto da seção 6.
- A assinatura exata de `read_many` e a organização interna das funções.
- Nomes de testes e fixtures.
- O comando exato de backfill compatível com a versão do Airflow da imagem (`apache/airflow:3.3.1`).
