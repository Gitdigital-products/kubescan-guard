from dataclasses import dataclass, field
from datetime import datetime, timezone
@dataclass
class Finding:
    severity: str; message: str; file_path: str = ""; line: int = 0; rule_id: str = ""; recommendation: str = ""
    def to_dict(self): return {"severity": self.severity, "message": self.message, "file_path": self.file_path, "line": self.line, "rule_id": self.rule_id, "recommendation": self.recommendation}
