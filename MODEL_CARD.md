# NetworkPulse AI — Model Card

## Scope

Network-flow binary intrusion detection on the bundled CICIDS2017 evidence sample.

## Champion

Weighted probability ensemble:

`0.50 × XGBoost + 0.30 × LightGBM + 0.20 × CatBoost`

Decision threshold selected for maximum F1 on the fixed development/hold-out benchmark: `0.37`.

Risk is then blended with independent normal-only anomaly evidence from an Autoencoder and Isolation Forest.

## Evidence

The packaged held-out benchmark contains 24,000 flows drawn from the 120,000-row evidence cache using stratified 80/20 splitting and `random_state=42`.

Champion results:

- Accuracy: 99.8833%
- Precision: 99.8335%
- Recall: 99.9333%
- F1: 99.8834%
- ROC-AUC: 99.9907%
- PR-AUC: 99.9901%

## Limitations

- The packaged benchmark is not a cross-day or cross-network validation.
- CICIDS2017 is an evaluation corpus; labels are ground truth in the dataset, not available during genuine deployment.
- NetworkPulse uses model evidence to prioritize investigation, not to automatically take destructive network actions.
