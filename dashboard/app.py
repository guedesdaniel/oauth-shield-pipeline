"""Local OAuth Shield dashboard. Run: streamlit run dashboard/app.py

A thin Streamlit shell: every number comes from oauth_shield.dashboard_queries, which only reads what
the pipeline wrote (nothing is re-scored here).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oauth_shield import dashboard_queries as dq  # noqa: E402

DATA_DIR = os.getenv("DATA_DIR", "data")

# Validated with the dataviz skill's validate_palette.js (light and dark): slot 1 blue, slot 2 orange,
# a single-hue blue ramp for magnitude, and the status "critical" red reserved for HIGH days.
PALETTES = {
    "light": {
        "hit": "#2a78d6",
        "error": "#eb6834",
        "ramp": ["#cde2fb", "#86b6ef", "#3987e5", "#1c5cab", "#0d366b"],
        "muted": "#52514e",
        "critical": "#d03b3b",
        "surface": "#ffffff",
    },
    "dark": {
        "hit": "#3987e5",
        "error": "#d95926",
        "ramp": ["#184f95", "#256abf", "#3987e5", "#6da7ec", "#b7d3f6"],
        "muted": "#c3c2b7",
        "critical": "#d03b3b",
        "surface": "#0e1117",
    },
}

st.set_page_config(page_title="OAuth Shield", page_icon="🛡️", layout="wide")
theme = getattr(getattr(st.context, "theme", None), "type", None)
P = PALETTES["dark" if theme == "dark" else "light"]


@st.cache_resource
def _connection(data_dir: str):
    return dq.connect(data_dir)


con = _connection(DATA_DIR).cursor()  # one cursor per session/rerun: DuckDB connections are not shared

missing = dq.missing_tables(con)
if missing:
    st.title("🛡️ OAuth Shield")
    st.warning(
        f"Ainda não há dados em `{DATA_DIR}` para: {', '.join(missing)}.\n\n"
        "Rode a DAG no Airflow ou o backfill (Etapa 2b do COMO_COMECAR):\n\n"
        "`docker compose exec airflow airflow backfill create --dag-id oauth_shield_daily "
        "--from-date 2026-10-24 --to-date 2026-11-22 --max-active-runs 1 --reprocess-behavior completed`"
    )
    st.stop()

dates = dq.available_dates(con)
with st.sidebar:
    st.header("Filtros")
    day = st.selectbox("Dia", dates, index=len(dates) - 1)
    start, end = st.select_slider("Período dos gráficos", options=dates, value=(dates[0], dates[-1]))
    st.caption(f"Dados: `{DATA_DIR}` · {len(dates)} dias")


def day_label(df: pd.DataFrame) -> pd.DataFrame:
    """'2026-11-22' -> '22/11', kept in date order for ordinal axes."""
    return df.assign(dia=df["dt"].str[8:10] + "/" + df["dt"].str[5:7])


def axis_order(df: pd.DataFrame) -> list[str]:
    return day_label(df.drop_duplicates("dt").sort_values("dt"))["dia"].tolist()


def show(chart: alt.Chart, data: pd.DataFrame, label: str) -> None:
    st.altair_chart(chart, width="stretch")
    with st.expander(f"Ver tabela: {label}"):
        st.dataframe(data, hide_index=True, width="stretch")


st.title("🛡️ OAuth Shield")
tab_overview, tab_ips, tab_detail = st.tabs(["Visão geral", "IPs suspeitos", "Detalhe"])

# ------------------------------------------------------------------ Visão geral
with tab_overview:
    s = dq.day_summary(con, day)
    cards = st.columns(5)
    cards[0].metric("Apps HIGH", s["high"])
    cards[1].metric("Apps MEDIUM", s["medium"])
    cards[2].metric("Ataques reais", s["attacks"])
    cards[3].metric("Precisão", "—" if s["precision"] is None else f"{s['precision']:.2f}")
    cards[4].metric("Recall", "—" if s["recall"] is None else f"{s['recall']:.2f}")
    if not s["baseline_ready"]:
        st.caption(
            "⚠️ Régua de subnets não pronta neste dia (menos de 14 dias de histórico): "
            "o sinal de subnet nova fica desligado."
        )

    left, right = st.columns(2)
    with left:
        st.subheader("Apps HIGH por dia")
        out = dq.daily_outcomes(con, start, end)
        if out.empty:
            st.info("Nenhum app HIGH no período.")
        else:
            out = day_label(out).assign(regua=lambda d: d["baseline_ready"].map({True: "pronta", False: "aquecendo"}))
            chart = (
                alt.Chart(out)
                .mark_bar(stroke=P["surface"], strokeWidth=2)
                .encode(
                    x=alt.X("dia:O", sort=axis_order(out), title=None, axis=alt.Axis(labelAngle=-45)),
                    y=alt.Y("n:Q", stack="zero", title="apps HIGH"),
                    color=alt.Color(
                        "outcome:N",
                        scale=alt.Scale(domain=["ataque real", "falso positivo"], range=[P["hit"], P["error"]]),
                        legend=alt.Legend(title=None, orient="top"),
                    ),
                    opacity=alt.condition(alt.datum.baseline_ready, alt.value(1.0), alt.value(0.4)),
                    tooltip=[
                        alt.Tooltip("dt:N", title="dia"),
                        alt.Tooltip("outcome:N", title="resultado"),
                        alt.Tooltip("n:Q", title="apps"),
                        alt.Tooltip("regua:N", title="régua de subnets"),
                    ],
                )
            )
            show(chart, out.drop(columns=["dia", "regua"]), "HIGH por dia")
            st.caption("Barras claras = dias de aquecimento da régua (sinal de subnet nova desligado).")

    with right:
        st.subheader("Sinais disparados por dia")
        sig = dq.daily_signals(con, start, end)
        if sig.empty:
            st.info("Nenhum sinal disparou no período.")
        else:
            sig = day_label(sig)
            chart = (
                alt.Chart(sig)
                .mark_rect(stroke=P["surface"], strokeWidth=2)
                .properties(height=260)
                .encode(
                    x=alt.X("dia:O", sort=axis_order(sig), title=None, axis=alt.Axis(labelAngle=-45)),
                    y=alt.Y("signal:N", sort=dq.SIGNALS, title=None, axis=alt.Axis(labelLimit=260)),
                    color=alt.Color("n:Q", scale=alt.Scale(range=P["ramp"]), title="apps"),
                    tooltip=[
                        alt.Tooltip("dt:N", title="dia"),
                        alt.Tooltip("signal:N", title="sinal"),
                        alt.Tooltip("n:Q", title="apps"),
                    ],
                )
            )
            show(chart, sig.drop(columns=["dia"]), "sinais por dia")
            st.caption("Um app pode disparar vários sinais; célula vazia = nenhum app.")

    st.subheader("Ataques por tipo: pegos x escaparam (dias com régua pronta)")
    att = dq.attacks_by_type(con, start, end)
    if att.empty:
        st.info("Nenhum dia com régua pronta no período.")
    else:
        long = att.melt(
            id_vars=["attack_type", "recall"], value_vars=["caught", "missed"], var_name="status", value_name="n"
        ).replace({"status": {"caught": "pegos", "missed": "escaparam"}})
        chart = (
            alt.Chart(long)
            .mark_bar(stroke=P["surface"], strokeWidth=2)
            .encode(
                y=alt.Y("attack_type:N", sort=att["attack_type"].tolist(), title=None, axis=alt.Axis(labelLimit=260)),
                x=alt.X("sum(n):Q", title="ataques"),
                color=alt.Color(
                    "status:N",
                    scale=alt.Scale(domain=["pegos", "escaparam"], range=[P["hit"], P["error"]]),
                    legend=alt.Legend(title=None, orient="top"),
                ),
                tooltip=[
                    alt.Tooltip("attack_type:N", title="tipo"),
                    alt.Tooltip("status:N"),
                    alt.Tooltip("n:Q", title="ataques"),
                    alt.Tooltip("recall:Q", format=".2f"),
                ],
            )
        )
        show(chart, att, "ataques por tipo")

    st.subheader(f"Erros do dia {day}")
    err = dq.day_errors(con, day)
    fp, fn = err[err["kind"] == "falso positivo"], err[err["kind"] == "ataque que escapou"]
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"**Falsos positivos ({len(fp)})** — o motivo vem de `benign_events`")
        st.dataframe(fp.drop(columns=["kind"]), hide_index=True, width="stretch")
    with c2:
        st.markdown(f"**Ataques que escaparam ({len(fn)})**")
        st.dataframe(fn.drop(columns=["kind"]), hide_index=True, width="stretch")

# ------------------------------------------------------------------ IPs suspeitos
with tab_ips:
    st.subheader("IPs com falhas, os que atingem mais apps primeiro")
    ips = dq.suspicious_ips(con, start, end)
    if ips.empty:
        st.info("Nenhum IP com falha no período.")
    else:
        st.dataframe(
            ips,
            hide_index=True,
            width="stretch",
            column_config={
                "max_clients": st.column_config.NumberColumn("máx. apps/dia"),
                "fail_ratio": st.column_config.NumberColumn("% falha", format="percent"),
                "hit_real_attack": st.column_config.CheckboxColumn("atingiu ataque real?"),
            },
        )
    st.subheader("Erros de scope vindos de uma /24 fora do usual (dias com régua pronta)")
    uns = dq.unusual_subnet_scope_errors(con, start, end)
    if uns.empty:
        st.info("Nenhum caso no período.")
    else:
        st.dataframe(uns, hide_index=True, width="stretch")

# ------------------------------------------------------------------ Detalhe
with tab_detail:
    mode = st.radio("Ver por", ["Aplicação", "IP"], horizontal=True)
    if mode == "Aplicação":
        opts = dq.app_options(con, start, end)
        labels = dict(zip(opts["client_id"], opts["max_score"], strict=True))
        app = st.selectbox(
            "Aplicação (maior score no período primeiro)", list(labels), format_func=lambda c: f"{c} (máx. {labels[c]})"
        )
        tl = dq.app_timeline(con, app, start, end) if app else pd.DataFrame()
        if tl.empty:
            st.info("Nenhum dado para esse filtro.")
        else:
            tl = day_label(tl)
            order = axis_order(tl)
            lines = tl.melt(
                id_vars=["dt", "dia"],
                value_vars=["total_requests", "expected_daily_volume"],
                var_name="serie",
                value_name="pedidos",
            ).replace({"serie": {"total_requests": "pedidos do dia", "expected_daily_volume": "volume esperado"}})
            base_x = alt.X("dia:O", sort=order, title=None, axis=alt.Axis(labelAngle=-45))
            line = (
                alt.Chart(lines)
                .mark_line(strokeWidth=2)
                .encode(
                    x=base_x,
                    y=alt.Y("pedidos:Q", title="pedidos"),
                    color=alt.Color(
                        "serie:N",
                        scale=alt.Scale(domain=["pedidos do dia", "volume esperado"], range=[P["hit"], P["muted"]]),
                        legend=alt.Legend(title=None, orient="top"),
                    ),
                    strokeDash=alt.condition(
                        alt.datum.serie == "volume esperado", alt.value([4, 4]), alt.value([1, 0])
                    ),
                    tooltip=[alt.Tooltip("dt:N", title="dia"), alt.Tooltip("serie:N"), alt.Tooltip("pedidos:Q")],
                )
            )
            high = (
                alt.Chart(tl[tl["risk_level"] == "HIGH"].assign(marca="dia HIGH"))
                .mark_point(filled=True, size=90, stroke=P["surface"], strokeWidth=2)
                .encode(
                    x=base_x,
                    y="total_requests:Q",
                    shape=alt.Shape("marca:N", legend=alt.Legend(title=None, orient="top")),
                    color=alt.value(P["critical"]),
                    tooltip=[
                        alt.Tooltip("dt:N", title="dia"),
                        alt.Tooltip("risk_score:Q", title="score"),
                        alt.Tooltip("reasons:N", title="motivos"),
                        alt.Tooltip("truth:N", title="verdade"),
                    ],
                )
            )
            st.altair_chart(line + high, width="stretch")
            st.dataframe(tl.drop(columns=["dia"]), hide_index=True, width="stretch")

            st.subheader(f"Subnets de {app} em {day} x régua")
            sn = dq.app_subnets(con, app, day)
            if sn.empty:
                st.info("Nenhum tráfego desse app nesse dia.")
            else:
                st.dataframe(sn, hide_index=True, width="stretch")
    else:
        top = dq.suspicious_ips(con, start, end, limit=1)
        ip = st.text_input("IP", value=top["source_ip"].iloc[0] if not top.empty else "").strip()
        act = dq.ip_activity(con, ip, start, end) if ip else pd.DataFrame()
        if act.empty:
            st.info("Nenhum dado para esse filtro.")
        else:
            attacked = act.loc[act["is_attack"], "client_id"].nunique()
            st.markdown(
                f"**{ip}** fez {int(act['requests'].sum())} pedidos em {act['client_id'].nunique()} apps "
                f"({attacked} eram ataque real no dia)."
            )
            st.dataframe(act, hide_index=True, width="stretch")
