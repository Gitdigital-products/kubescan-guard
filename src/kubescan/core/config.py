from dataclasses import dataclass, field
from pathlib import Path
@dataclass
class Config:
    project_path: Path = field(default_factory=lambda: Path.cwd())
    severity_threshold: str = "low"
