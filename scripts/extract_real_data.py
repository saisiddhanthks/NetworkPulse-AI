"""Prepare the raw CICIDS2017 CSVs used for optional retraining.

The running application only needs the bundled evidence cache and trained models,
so this step is optional. The raw corpus (~2.8M flows) is too large for GitHub;
download it from the Canadian Institute for Cybersecurity and either:
  * place the 8 MachineLearningCVE CSVs in backend/data/raw/extracted/, or
  * place them packed as backend/data/raw/cicids2017_real_data.tar.xz.

Usage:
  python scripts/extract_real_data.py            # optional check (never fails setup)
  python scripts/extract_real_data.py --require  # fail if the corpus is missing (retraining)
"""
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'backend' / 'data' / 'raw'
ARCHIVE = RAW / 'cicids2017_real_data.tar.xz'
OUT = RAW / 'extracted'
EXPECTED = [
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-workingHours.pcap_ISCX.csv',
]
REQUIRE = '--require' in sys.argv


def missing():
    return [n for n in EXPECTED if not (OUT / n).exists()]


OUT.mkdir(parents=True, exist_ok=True)
if missing() and ARCHIVE.exists():
    print('Extracting the CICIDS2017 corpus...')
    with tarfile.open(ARCHIVE, 'r:xz') as tar:
        tar.extractall(OUT)

gone = missing()
if not gone:
    print(f'CICIDS2017 corpus: OK ({len(EXPECTED)} CSV files)')
    sys.exit(0)

msg = ('CICIDS2017 raw corpus not found (only needed for retraining).\n'
       'Download: https://www.unb.ca/cic/datasets/ids-2017.html (MachineLearningCSV)\n'
       f'Place the CSVs in: {OUT}')
print(msg)
sys.exit(1 if REQUIRE else 0)
