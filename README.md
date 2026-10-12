# 🛡️ EventLog Analyzer — AI-Powered Windows Event Log Anomaly Detection

An end-to-end machine learning project that detects security incidents and operational
failures in Windows Event Logs — **without labeled data, without an enterprise SIEM,
and without spending a dollar.**

Built by **Rittu Vijai** — Senior Endpoint Engineer (Microsoft Intune, Entra ID,
Nexthink/DEX, KQL) — as a hands-on demonstration of applied ML for endpoint security
and IT operations.

---

## What it does

```
  Raw Windows Event Logs (CSV)
            │
            ▼
  ┌─────────────────────┐
  │ Feature engineering  │  per-host, per-hour behavior vectors (11 features:
  │                      │  logon failures, off-hours ratio, process entropy…)
  └─────────┬───────────┘
            ▼
     ┌──────┴──────┐
     ▼             ▼
 ┌───────┐   ┌───────────┐
 │ ML    │   │ Signature │  hybrid: Isolation Forest finds novel behavioral
 │ stage │   │ rules     │  deviations; deterministic rules catch known-bad
 └───┬───┘   └─────┬─────┘  patterns (brute force, ransomware, log clearing)
     └──────┬──────┘
            ▼ max(score)
  ┌─────────────────────┐
  │ Incident summarizer  │  clusters anomalies → plain-English incident reports
  │                      │  with severity + recommended next step
  └─────────┬───────────┘
            ▼
   Streamlit dashboard: timeline · incident cards · host risk ranking · event search
```

## The 5 demo incident scenarios

The synthetic dataset ships with five injected, realistic attack/ops scenarios:

| # | Scenario | What the ML catches |
|---|----------|---------------------|
| 1 | **Brute-force logon** | 47 failed logons (Event 4625) in 3 min from one external IP, then a success |
| 2 | **Off-hours admin** | Domain-admin Kerberos tickets at 3 AM from a sales workstation, 3 nights running |
| 3 | **Ransomware pattern** | 320 mass file-access events in minutes + `vssadmin delete shadows` |
| 4 | **Bad-patch outage** | Correlated service crashes (7031/7034) across 200+ hosts in 45 min |
| 5 | **Malicious process chain** | `winword.exe → powershell -enc → mimikatz →` Security log cleared (1102) |

## Quickstart (2 commands)

```bash
# 1. Create the demo dataset (~10k endpoints × 30 days of realistic logs)
python generate_logs.py --hosts 100 --days 30 --out sample_logs/events.csv

# 2. Launch the dashboard
streamlit run app.py
```

For the full-scale demo: `--hosts 10000` (takes a few minutes to generate).

To analyze your **own** logs instead, export Windows Event Viewer → CSV with columns
`timestamp, host, user, event_code, log, description, process, source_ip`
(or just upload any CSV — the sidebar accepts uploads in the same schema).

## Project structure

```
ai-poc-eventlog-analyzer/
├── generate_logs.py   # Synthetic enterprise event-log generator (5 incident scenarios)
├── detector.py        # Feature engineering + Isolation Forest anomaly detector
├── summarizer.py      # Rule-based plain-English incident summaries + playbook actions
├── app.py             # Streamlit dashboard (timeline, incidents, host risk, explorer)
├── requirements.txt   # 100% free / open-source dependencies
└── sample_logs/       # Generated demo data (created by generate_logs.py)
```

## Tech stack

- **ML:** scikit-learn `IsolationForest` (unsupervised — detects *unknown* unknowns)
- **Data:** pandas, numpy — 11 engineered behavioral features per host-hour
- **Dashboard:** Streamlit + Plotly — timeline charts, risk ranking, incident cards
- **Cost:** $0 — every dependency is free and open source

## Why hybrid (ML + rules)?

Pure unsupervised ML has a known blind spot: a point that is *extremely*
anomalous in one feature but normal in ten others can score *lower* than a
point that is merely odd in several features. A 47-failed-logon brute force
is the textbook example — I verified this empirically during development.

Real UEBA/SIEM platforms solve it the same way this project does: ML
(Isolation Forest) for novel behavioral deviations, deterministic signatures
for known-bad patterns. The detector takes the maximum of both signals.

## Why unsupervised?

In real SOCs, you can't label attacks you haven't seen yet. Supervised models only
catch yesterday's threats. Isolation Forest learns "what normal looks like" per host
and flags behavioral deviations — the same principle behind modern UEBA platforms.

## Sample output

> **INC-001 · CRITICAL · Possible ransomware encryption in progress**
> 320 mass file-access events erupted on WS-ENG-1042 over 6 minutes, followed by a
> shadow-copy deletion command (vssadmin) — the classic ransomware one-two punch:
> encrypt, then destroy backups.
> **Recommended:** ISOLATE THE HOST IMMEDIATELY — disconnect from network…

## Roadmap

- [ ] Natural-language event search ("show me failed logons last Tuesday")
- [ ] KQL query export for Microsoft Sentinel / Defender hunting
- [ ] Real-time streaming mode (watch a live event feed)
- [ ] Model comparison: Isolation Forest vs. Autoencoder vs. LOF

---

*Built to show what's possible when endpoint expertise meets applied ML.
Open to Senior Endpoint / Cloud Ops / DEX roles — DFW or remote (US).*
