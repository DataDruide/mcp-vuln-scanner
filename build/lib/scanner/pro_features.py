import os
from .license import LicenseValidator

_license_cache = None

def get_license():
    global _license_cache
    if _license_cache is None:
        license_key = os.environ.get("MCP_SCANNER_LICENSE") or os.environ.get("MCP_SCANNER_KEY")
        if license_key:
            validator = LicenseValidator()
            _license_cache = validator.validate(license_key)
        else:
            _license_cache = {"valid": False, "plan": "free", "features": []}
    return _license_cache

def is_pro_feature_enabled(feature_name: str) -> bool:
    license = get_license()
    pro_features = ["cve_check", "html_report", "sarif_report", "live_scan", "pdf_report"]
    if feature_name in pro_features:
        return license.get("plan") in ["pro", "enterprise"] or license.get("valid", False)
    return True

def get_active_plan() -> str:
    return get_license().get("plan", "free")
