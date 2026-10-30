"""Extract the raw CICIDS2017 CSVs, if the archive is present.

The raw corpus (~1.1 GB) is not stored in this repository. The app runs from the
bundled 120,000-flow evidence cache and trained models; the raw CSVs are only
needed to retrain (backend/train.py). To retrain, download CICIDS2017 from
https://www.unb.ca/cic/datasets/ids-2017.html and place the 8 CSVs in
backend/data/raw/extracted/.
"""
from pathlib import Path
import tarfile, sys
ROOT=Path(__file__).resolve().parents[1]
archive=ROOT/'backend'/'data'/'raw'/'cicids2017_real_data.tar.xz'
out=ROOT/'backend'/'data'/'raw'/'extracted'
out.mkdir(parents=True,exist_ok=True)
expected=[
'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv','Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv','Friday-WorkingHours-Morning.pcap_ISCX.csv','Monday-WorkingHours.pcap_ISCX.csv','Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv','Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv','Tuesday-WorkingHours.pcap_ISCX.csv','Wednesday-workingHours.pcap_ISCX.csv']
missing=[n for n in expected if not (out/n).exists()]
if missing and not archive.exists():
    print('Raw CICIDS2017 CSVs not present: OK for running the app (uses the bundled evidence cache).')
    print('To retrain, download CICIDS2017 and place the 8 CSVs in backend/data/raw/extracted/.')
    sys.exit(0)
if missing:
    print('Extracting the CICIDS2017 corpus...')
    with tarfile.open(archive,'r:xz') as tar: tar.extractall(out)
missing=[n for n in expected if not (out/n).exists()]
if missing:
    print('ERROR: extraction incomplete:'); [print('  -',n) for n in missing]; sys.exit(1)
print('Raw CICIDS2017 files: OK (',len(expected),'CSV files )')
