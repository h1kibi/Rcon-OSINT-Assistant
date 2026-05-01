import os
import re
from datetime import datetime
from pathlib import Path
from loguru import logger


# Base directory for analysis storage
ANALYSIS_BASE = Path("data") / "analyses"


def ensure_dir(path: Path):
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_vuln_dir(vuln_id: str) -> Path:
    """Get or create directory for a vulnerability's analyses.
    Handles CVE-xxxx, GHSA-xxx, OSV-xxx IDs."""
    if not vuln_id:
        vuln_id = "unknown"
    # Sanitize for filesystem: keep alphanumeric, hyphens, underscores
    safe_name = re.sub(r'[^\w\-]', '_', vuln_id)
    vuln_dir = ANALYSIS_BASE / safe_name
    ensure_dir(vuln_dir)
    return vuln_dir


def save_analysis(vuln_id: str, content: str, model: str = "") -> str:
    """
    Save AI analysis to a markdown file.
    Returns the file path.
    """
    vuln_dir = get_vuln_dir(vuln_id)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"analysis_{timestamp}.md"
    filepath = vuln_dir / filename

    md_content = f"""# AI 安全分析报告

**漏洞编号**: {vuln_id}
**分析时间**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**分析模型**: {model or 'Unknown'}

---

{content}

---
*由 Rcon AI 自动生成*
"""
    filepath.write_text(md_content, encoding="utf-8")
    logger.info(f"Analysis saved: {filepath}")
    return str(filepath)


def list_analyses(vuln_id: str) -> list[dict]:
    """
    List all analysis files for a vulnerability.
    Returns list of {filename, path, time, size}.
    """
    vuln_dir = get_vuln_dir(vuln_id)
    if not vuln_dir.exists():
        return []

    results = []
    for f in sorted(vuln_dir.glob("analysis_*.md"), reverse=True):
        stat = f.stat()
        try:
            ts_str = f.stem.replace("analysis_", "")
            time_obj = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
            time_str = time_obj.strftime("%Y-%m-%d %H:%M:%S")
        except:
            time_str = "Unknown"

        results.append({
            "filename": f.name,
            "path": str(f),
            "time": time_str,
            "size": f"{stat.st_size / 1024:.1f} KB",
        })

    return results


def read_analysis(filepath: str) -> str:
    """Read an analysis file."""
    try:
        return Path(filepath).read_text(encoding="utf-8")
    except Exception as e:
        return f"读取失败: {e}"


def delete_analysis(filepath: str) -> bool:
    """Delete an analysis file."""
    try:
        Path(filepath).unlink()
        return True
    except Exception as e:
        logger.error(f"Failed to delete {filepath}: {e}")
        return False


def get_analysis_count(vuln_id: str) -> int:
    """Get number of analyses for a vulnerability."""
    vuln_dir = get_vuln_dir(vuln_id)
    if not vuln_dir.exists():
        return 0
    return len(list(vuln_dir.glob("analysis_*.md")))
