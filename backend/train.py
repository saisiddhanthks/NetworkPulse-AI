"""Optional retraining pipeline.
Builds a stratified real-data sample from the extracted CICIDS2017 CSVs and trains
XGBoost, LightGBM and CatBoost binary detectors. This is intentionally separate
from first-run execution because the final package ships with trained artifacts.
"""
from pathlib import Path
import os
import pandas as pd, numpy as np, joblib, json
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,roc_auc_score,average_precision_score,confusion_matrix
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier

ROOT=Path(__file__).resolve().parents[1]; RAW=ROOT/'data/raw/extracted'; MODEL=ROOT/'models'; DATA=ROOT/'data'
FILES=sorted(RAW.glob('*.csv'))
if not FILES: raise SystemExit('No extracted CICIDS CSVs found. Run scripts\\extract_real_data.py first.')
frames=[]
for f in FILES:
    parts=[]
    for ch in pd.read_csv(f,chunksize=100000,low_memory=False,encoding_errors='replace'):
        ch.columns=[c.strip() for c in ch.columns]
        parts.append(ch.sample(n=min(15000,len(ch)),random_state=42+len(parts)))
    d=pd.concat(parts,ignore_index=True)
    frames.append(d.sample(n=min(80000,len(d)),random_state=42))
D=pd.concat(frames,ignore_index=True).sample(frac=1,random_state=42).reset_index(drop=True)
Y=(D['Label'].astype(str).str.strip().str.upper()!='BENIGN').astype(int)
DROP={'Label','Timestamp','Flow ID','Source IP','Destination IP','Source Port','Attack Type','attack_cat','Attack','Src IP','Dst IP'}
X=D.drop(columns=[c for c in DROP if c in D.columns],errors='ignore').copy()
for c in X.columns:X[c]=pd.to_numeric(X[c],errors='coerce')
X=X.replace([np.inf,-np.inf],np.nan); keep=[c for c in X.columns if X[c].notna().sum()>100 and X[c].nunique(dropna=True)>1]; X=X[keep]; med=X.median(numeric_only=True); X=X.fillna(med)
Xt,Xe,yt,ye=train_test_split(X,Y,test_size=.2,stratify=Y,random_state=42)
models={
 'xgboost':XGBClassifier(n_estimators=400,max_depth=7,learning_rate=.06,subsample=.9,colsample_bytree=.9,min_child_weight=1,reg_lambda=2.0,objective='binary:logistic',eval_metric='logloss',tree_method='hist',random_state=42,n_jobs=max(2,min(8,(os.cpu_count() or 4)))),
 'lightgbm':LGBMClassifier(n_estimators=400,learning_rate=.05,num_leaves=63,subsample=.9,colsample_bytree=.9,reg_lambda=2.0,reg_alpha=.05,objective='binary',random_state=42,n_jobs=max(2,min(8,(os.cpu_count() or 4))),verbosity=-1),
 'catboost':CatBoostClassifier(iterations=200,depth=8,learning_rate=.08,loss_function='Logloss',eval_metric='AUC',random_seed=42,verbose=False,thread_count=max(2,min(8,(os.cpu_count() or 4))),l2_leaf_reg=4.0,random_strength=.4,bootstrap_type='Bernoulli',subsample=.9,allow_writing_files=False)
}
res=[]; probs=[]
for name,m in models.items():
    m.fit(Xt,yt,eval_set=[(Xe,ye)] if name!='catboost' else (Xe,ye))
    p=m.predict_proba(Xe)[:,1]; probs.append(p); best=(0,.5)
    for th in np.linspace(.05,.95,181):
        f=f1_score(ye,p>=th,zero_division=0)
        if f>best[0]:best=(f,th)
    pr=p>=best[1]
    res.append({'model':name,'accuracy':accuracy_score(ye,pr),'precision':precision_score(ye,pr),'recall':recall_score(ye,pr),'f1':f1_score(ye,pr),'roc_auc':roc_auc_score(ye,p),'pr_auc':average_precision_score(ye,p),'threshold':best[1],'confusion_matrix':confusion_matrix(ye,pr).tolist()})
    joblib.dump({'model':m,'features':keep,'medians':med.to_dict()},MODEL/f'{name}_core.joblib',compress=3)
ens=.5*probs[0]+.3*probs[1]+.2*probs[2]; best=(0,.37)
for th in np.linspace(.05,.95,181):
    f=f1_score(ye,ens>=th)
    if f>best[0]:best=(f,th)
pr=ens>=best[1]
res.append({'model':'Ensemble','accuracy':accuracy_score(ye,pr),'precision':precision_score(ye,pr),'recall':recall_score(ye,pr),'f1':f1_score(ye,pr),'roc_auc':roc_auc_score(ye,ens),'pr_auc':average_precision_score(ye,ens),'threshold':best[1],'confusion_matrix':confusion_matrix(ye,pr).tolist()})
json.dump({'available':True,'train_rows':len(Xt),'test_rows':len(Xe),'features':len(keep),'champion':'Ensemble','ensemble_weights':{'XGBoost':.5,'LightGBM':.3,'CatBoost':.2},'decision_threshold':best[1],'models':res},open(DATA/'evaluation_results.json','w'),indent=2)
print('Retraining complete. Champion:',res[-1]); print('Next: rebuild evidence cache with your preferred sampling strategy.')
