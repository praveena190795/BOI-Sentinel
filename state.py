# state.py
from typing import TypedDict, Dict, Any, List, Optional

class AnalysisState(TypedDict):
    apk_path: str
    package_name: str
    apk_hash: Optional[str]
    metadata_score: Optional[int]
    known_malware: Optional[bool]
    
    raw_static_json: Any  # Allow flex verification type
    filtered_static_data: Any
    dynamic_log_data: str
    
    mitre_mappings: Optional[List[Dict[str, Any]]]
    risk_score: Optional[int]
    verdict_justification: Optional[str]
    
    final_report_markdown: str
    dynamic_ml_prediction: Optional[str]
dynamic_ml_confidence: Optional[float]
detected_capabilities: Optional[List[str]]