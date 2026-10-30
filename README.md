# NetworkPulse AI — Network Intrusion Detection with an AI Analyst

An evidence-first network intrusion and anomaly-detection console built on the **CICIDS2017** dataset, with a tool-calling AI analyst that investigates alerts and explains them in plain language.

Computer Networks course project, VIT Vellore (2026) — Sai Siddhanth K S. An IEEE-format paper on the system is in [`docs/`](docs/NetworkPulse_AI_IEEE_Paper.pdf).

## What this build contains

- A ready-to-run evidence cache of 120,000 real flows sampled from the full CICIDS2017 corpus (2.83M flows across 8 CSVs).
- Trained model artefacts in `backend/models/`, so the app runs without retraining.
- Supervised ensemble: **XGBoost + LightGBM + CatBoost**.
- Normal-only anomaly evidence: **Autoencoder + Isolation Forest**.
- Model-consensus score, confidence, local XGBoost contributions and reconstruction deviations.
- Autonomous agent loop: **Observe → Detect → Inspect → Correlate → Reason → Recommend**.
- Groq reasoning integration using the configured `GROQ_MODEL`.
- Evidence tools available to the agent: summary, priority flows, event inspection, related events, evaluation metrics, attack distribution and feature importance.
- Bounded tool orchestration with a guaranteed final-synthesis path; the UI does not blank if a model/tool call fails.
- Interactive Command Center, Investigation Deck, Agent cockpit, Model Lab, Threat Intel workspace, reports, command palette and CSV analysis upload.
- No Node/npm dependency. The frontend is served directly by FastAPI for a simpler and more reliable demo.

## First run on Windows

1. Clone this repository.
2. Copy `backend/.env.example` to `backend/.env` and add your Groq API key (optional — the dashboard and models work without it).
3. Double-click `start.bat`.
4. The script runs the one-time setup automatically if the Python environment is missing.
5. The dashboard opens at **http://127.0.0.1:8000/**.

PowerShell users can also run:

```powershell
.\start.bat
```

For a detailed environment check:

```text
scripts\doctor.bat
```

## API

- `/api/ping` — startup check
- `/api/health` — engine/model/LLM configuration state
- `/api/dashboard` — dashboard payload
- `/api/events` — priority event search/filter
- `/api/events/{event_id}` — event dossier + explanation
- `/api/agent` — autonomous-agent state
- `/api/agent/run` — run one bounded investigation cycle
- `/api/agent/chat` — evidence-grounded agent chat
- `/api/evaluation` — held-out benchmark
- `/api/models/{model}/importance` — global model importance
- `/api/intel/ip/{ip}` — optional VirusTotal/AbuseIPDB enrichment
- `/api/report/{event_id}` — investigation report

## Data and methodology

CICIDS2017 is a Canadian Institute for Cybersecurity intrusion-detection dataset with more than 80 network-flow features generated from captured traffic. The corpus covers the Monday–Friday CSV files and includes normal traffic plus DDoS, PortScan, Bot, DoS, Patator, Web Attack, Infiltration and Heartbleed labels.

The packaged benchmark uses a fixed **80/20 stratified hold-out** over the 120,000-row sampled real-data evidence cache (random_state=42). The benchmark is designed to compare the models used by this package; it is **not** a cross-day deployment benchmark and should not be described as one.

### Packaged held-out benchmark

| Model | F1 | Precision | Recall | ROC-AUC |
| --- | ---: | ---: | ---: | ---: |
| XGBoost | 99.8709% | 99.8169% | 99.9250% | 99.9877% |
| LightGBM | 99.8709% | 99.8335% | 99.9083% | 99.9881% |
| CatBoost | 99.8500% | 99.8168% | 99.8833% | 99.9849% |
| **Ensemble** | **99.8834%** | **99.8335%** | **99.9333%** | **99.9907%** |

These metrics are evidence for this exact packaged benchmark split. They are not a promise of performance on unseen networks.

## Why these models

Tree boosting is a strong fit for CICIDS-style tabular network-flow telemetry. XGBoost, LightGBM and CatBoost all provide efficient gradient-boosted tree classifiers and feature-importance capabilities. The package uses all three and combines their probabilities because the ensemble slightly improves the held-out F1/ROC-AUC in the packaged benchmark. A normal-only Autoencoder and Isolation Forest remain independent anomaly signals instead of replacing the labeled supervised detector.

Groq's documented local tool-calling pattern keeps tool execution in the application, which is exactly how NetworkPulse controls evidence gathering before handing the evidence packet to the LLM for reasoning.

## Research references

- CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- XGBoost docs: https://xgboost.readthedocs.io/
- LightGBM docs: https://lightgbm.readthedocs.io/
- CatBoost classifier docs: https://catboost.ai/docs/en/concepts/python-reference_catboostclassifier
- Scikit-learn HistGradientBoosting: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.HistGradientBoostingClassifier.html
- Groq tool use: https://console.groq.com/docs/tool-use/overview
- Groq local tool calling: https://console.groq.com/docs/tool-use/local-tool-calling
- VirusTotal IP API: https://docs.virustotal.com/reference/ip-info
- AbuseIPDB API: https://docs.abuseipdb.com/index.html

## Raw data and retraining

The raw CICIDS2017 CSVs (~1.1 GB) are not stored in this repository. They are only needed to retrain: download them from the [CIC website](https://www.unb.ca/cic/datasets/ids-2017.html), place the 8 CSVs in `backend/data/raw/extracted/`, then run `scripts\retrain_real_data.bat`.

## Security note

API keys live only in `backend/.env`, which is git-ignored and never sent to the browser UI. Optional VirusTotal and AbuseIPDB keys are blank by default.
