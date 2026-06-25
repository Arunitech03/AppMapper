"""Role-based access comparison (discovery-only).

Maps which endpoints each configured role can reach and computes the differences
between roles. This is attack-surface mapping per identity — it issues only
read-only GET requests with each role's own credentials and never attempts
authorization bypass, privilege escalation, or exploitation.
"""

from modules.access.comparison import (
    access_matrix,
    build_access_records,
    role_difference,
)

__all__ = ["build_access_records", "access_matrix", "role_difference"]
