from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import joblib
import numpy as np
import pandas as pd
from .config import MODEL_DIR, EVAL_PATH

DROP = {
    'Label','label','Timestamp','Flow ID','Source IP','Destination IP','Source Port',
    'Src IP','Dst IP','Attack Type','attack_cat','Attack','event_id','row_id',
    'risk','severity','anomaly_score','supervised_probability','reconstruction_error',
    'anomaly','port','destination_port','xgb_probability','lgbm_probability',
    'catboost_probability','ensemble_probability','model_agreement','confidence',
    'isolation_score'
}

class Detector:
    def __init__(self):
        self.xgb = self._load('xgboost_core.joblib')
        self.lgbm = self._load('lightgbm_core.joblib')
        self.cat = self._load('catboost_core.joblib')
        self.anomaly = self._load('anomaly_core.joblib')
        self.weights = {'XGBoost': 0.50, 'LightGBM': 0.30, 'CatBoost': 0.20}
        self.threshold = 0.37
        self.ready = all(x is not None for x in (self.xgb, self.lgbm, self.cat, self.anomaly))

    def _load(self, name):
        path = MODEL_DIR / name
        return joblib.load(path) if path.exists() else None

    def _numeric(self, df: pd.DataFrame, features=None, medians=None):
        x = df.copy()
        x.columns = [str(c).strip() for c in x.columns]
        x = x.drop(columns=[c for c in DROP if c in x.columns], errors='ignore')
        for c in x.columns:
            x[c] = pd.to_numeric(x[c], errors='coerce')
        x = x.replace([np.inf, -np.inf], np.nan)
        if features is not None:
            x = x.reindex(columns=features)
        if medians:
            x = x.fillna(pd.Series(medians))
        return x.fillna(0.0)

    def _model_prob(self, pack, df):
        X = self._numeric(df, pack['features'], pack.get('medians'))
        return pack['model'].predict_proba(X)[:, 1]

    def _anomaly_matrix(self, df):
        x = self._numeric(df, self.anomaly['columns'], self.anomaly.get('feature_medians'))
        return self.anomaly['scaler'].transform(self.anomaly['imputer'].transform(x))

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        if not self.ready:
            raise RuntimeError('Model bundle is incomplete.')
        px = self._model_prob(self.xgb, df)
        pl = self._model_prob(self.lgbm, df)
        pc = self._model_prob(self.cat, df)

        # Normal-only anomaly evidence from the packaged Autoencoder + Isolation Forest.
        xa = self._anomaly_matrix(df)
        recon = self.anomaly['autoencoder'].predict(xa)
        err = np.mean((xa - recon) ** 2, axis=1)
        ae_score = np.clip(100 * (1 - np.exp(-err / max(self.anomaly['threshold'], 1e-9) / 1.5)), 0, 99)
        iso_raw = -self.anomaly['isolation'].decision_function(xa)
        iso_score = np.clip(
            100 * (iso_raw - np.percentile(iso_raw, 2)) /
            (np.percentile(iso_raw, 98) - np.percentile(iso_raw, 2) + 1e-9), 0, 100
        )

        ensemble = 0.50 * px + 0.30 * pl + 0.20 * pc
        disagreement = np.std(np.vstack([px, pl, pc]), axis=0)
        agreement = np.clip(1 - 2 * disagreement, 0, 1)
        risk = np.clip(100 * (0.82 * ensemble + 0.13 * (ae_score / 100) + 0.05 * (iso_score / 100)), 0, 99)
        severity = np.select([risk >= 85, risk >= 65, risk >= 40], ['Critical', 'High', 'Medium'], default='Low')
        confidence = np.clip(100 * (0.72 * np.maximum(ensemble, 1 - ensemble) + 0.28 * agreement), 0, 100)
        return pd.DataFrame({
            'xgb_probability': px, 'lgbm_probability': pl, 'catboost_probability': pc,
            'ensemble_probability': ensemble, 'model_agreement': agreement, 'confidence': confidence,
            'reconstruction_error': err, 'anomaly_score': ae_score, 'isolation_score': iso_score,
            'risk': risk, 'anomaly': ensemble >= self.threshold, 'severity': severity
        }, index=df.index)

    def explain(self, row: pd.DataFrame) -> dict[str, Any]:
        pred = self.predict(row).iloc[0].to_dict()
        xa = self._anomaly_matrix(row)
        recon = self.anomaly['autoencoder'].predict(xa)
        deviations = np.abs(xa[0] - recon[0])
        top_ae = sorted(zip(self.anomaly['columns'], deviations), key=lambda z: z[1], reverse=True)[:10]

        contributions = []
        try:
            import xgboost as xgb
            X = self._numeric(row, self.xgb['features'], self.xgb.get('medians'))
            dm = xgb.DMatrix(X, feature_names=self.xgb['features'])
            vals = self.xgb['model'].get_booster().predict(dm, pred_contribs=True)[0][:-1]
            for c, v in sorted(zip(self.xgb['features'], vals), key=lambda z: abs(z[1]), reverse=True)[:10]:
                contributions.append({'feature': c, 'contribution': round(float(v), 5)})
        except Exception:
            pass

        votes = {
            'XGBoost': float(self.predict(row)['xgb_probability'].iloc[0]),
            'LightGBM': float(self.predict(row)['lgbm_probability'].iloc[0]),
            'CatBoost': float(self.predict(row)['catboost_probability'].iloc[0]),
        }
        return {
            **{k: float(v) if isinstance(v, (np.floating, float, int)) else str(v) for k, v in pred.items()},
            'top_reconstruction_deviations': [
                {'feature': c, 'deviation': round(float(v), 5)} for c, v in top_ae
            ],
            'xgb_contributions': contributions,
            'model_votes': votes,
            'ensemble_weights': self.weights,
            'decision_threshold': self.threshold,
            'method_note': 'Risk blends a supervised three-model ensemble with normal-only anomaly evidence.'
        }

    def model_importance(self, which='xgboost'):
        packs = {'xgboost': self.xgb, 'lightgbm': self.lgbm, 'catboost': self.cat}
        pack = packs.get(which, self.xgb)
        model = pack['model']; feats = pack['features']
        try:
            vals = model.feature_importances_
        except Exception:
            vals = np.zeros(len(feats))
        return [
            {'feature': f, 'importance': round(float(v), 6)}
            for f, v in sorted(zip(feats, vals), key=lambda z: z[1], reverse=True)[:20]
        ]

detector = Detector()
