from pathlib import Path
import os

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / 'data'
MODEL_DIR = ROOT / 'models'
RAW_DIR = DATA_DIR / 'raw'
EVENT_CACHE = DATA_DIR / 'event_cache.csv.gz'
AGENT_LOG = DATA_DIR / 'agent_activity.json'
EVAL_PATH = DATA_DIR / 'evaluation_results.json'
IMPORTANCE_DIR = DATA_DIR


def _load_env_file(path: Path):
    if not path.exists():
        return
    for raw in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        k = k.strip(); v = v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v

_load_env_file(ROOT / '.env')
_load_env_file(ROOT / '.env.example')

GROQ_API_KEY = os.getenv('GROQ_API_KEY', '').strip()
GROQ_MODEL = os.getenv('GROQ_MODEL', 'openai/gpt-oss-120b').strip()
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '').strip()
AGENT_INTERVAL_SECONDS = int(os.getenv('AGENT_INTERVAL_SECONDS', '180'))
DISABLE_AGENT_AUTORUN = os.getenv('DISABLE_AGENT_AUTORUN','0') == '1'
