import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from app.core.config import settings


@dataclass
class SweepResult:
    status: str  # PASSED / PENDING / QUARANTINED
    report: dict


class MalwareScanService:
    BASE = "https://www.virustotal.com/api/v3/files"

    def __init__(self) -> None:
        self.api_key = settings.virustotal_api_key

    def check_hash(self, file_hash: str) -> SweepResult:
        if not self.api_key:
            return SweepResult(status="PASSED", report={"reason": "virustotal disabled"})

        req = urllib.request.Request(f"{self.BASE}/{file_hash}", headers={"x-apikey": self.api_key})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return SweepResult(status="PENDING", report={"reason": "hash_unknown"})
            return SweepResult(status="PENDING", report={"reason": f"vt_http_{exc.code}"})
        except Exception as exc:
            return SweepResult(status="PENDING", report={"reason": f"vt_unavailable:{exc}"})

        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))

        if malicious > 0 or suspicious > 2:
            return SweepResult(status="QUARANTINED", report={"stats": stats})

        return SweepResult(status="PASSED", report={"stats": stats})


malware_scan_service = MalwareScanService()
