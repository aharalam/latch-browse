import os
from pathlib import Path
import shutil
import subprocess


def test_compiled_research_polling(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = {**os.environ, 'PYTHONIOENCODING': 'utf-8', 'LITELLM_LOCAL_MODEL_COST_MAP': 'True'}
    compile_result = subprocess.run([shutil.which('jac'), 'jac2js', 'components/ResearchWorkspace.cl.jac'], cwd=root, env=env, capture_output=True, text=True, encoding='utf-8', timeout=120)
    assert compile_result.returncode == 0, compile_result.stderr
    js = tmp_path / 'workspace.js'
    js.write_text(compile_result.stdout, encoding='utf-8')
    result = subprocess.run([shutil.which('node'), str(root / 'tests/polling_regression.cjs'), str(js)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
