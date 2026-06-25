"""Feature 7: Pentest checklist generator.

Maps detected sensitive-function categories to manual-review checklist items.
These are *recommendations for a human tester* — AppMapper performs none of them.
"""

from __future__ import annotations

from models.schemas import ChecklistItem, SensitiveFunction

# Specific function label -> list of manual review items.
CHECKLIST_TEMPLATES: dict[str, list[str]] = {
    "Upload": [
        "Upload validation review (allowed types / size)",
        "Extension filtering review",
        "MIME validation review",
        "Stored file path / overwrite review",
    ],
    "Attachment": ["Attachment handling & access-control review"],
    "Document": ["Document access-control (IDOR) review"],
    "Avatar": ["Image processing / SSRF-via-URL review"],
    "Export": [
        "CSV injection review",
        "Authorization review on export",
        "Sensitive data exposure review",
    ],
    "Download": ["Authorization review on download", "Path traversal review"],
    "Report": ["Authorization review", "Sensitive data exposure review"],
    "CSV": ["CSV injection review"],
    "PDF": ["Server-side rendering / SSRF review"],
    "Excel": ["Formula injection review"],
    "Login": ["Rate-limiting review", "Session fixation review", "Credential transport review"],
    "Logout": ["Session invalidation review"],
    "Register": ["Account enumeration review", "Input validation review"],
    "Password Reset": ["Reset-token strength/expiry review", "Account enumeration review"],
    "MFA": ["MFA bypass / fallback review"],
    "Users": ["Authorization (IDOR) review", "Mass-assignment review"],
    "Roles": ["Role validation review", "Authorization review"],
    "Groups": ["Authorization review"],
    "Permissions": ["Authorization / privilege model review"],
    "Admin": ["Role validation review", "Authorization review", "Forced-browsing review"],
    "Settings": ["Authorization review", "Sensitive configuration exposure review"],
    "Configuration": ["Authorization review", "Secrets exposure review"],
    "System": ["Authorization review"],
}


def generate_checklist(functions: list[dict | SensitiveFunction]) -> list[ChecklistItem]:
    """Generate de-duplicated checklist items from detected sensitive functions."""
    items: list[ChecklistItem] = []
    seen: set[tuple[str, str, str]] = set()

    for fn in functions:
        category = fn.category if isinstance(fn, SensitiveFunction) else fn.get("category", "")
        label = fn.subcategory if isinstance(fn, SensitiveFunction) else fn.get("subcategory")
        endpoint = fn.endpoint if isinstance(fn, SensitiveFunction) else fn.get("endpoint")
        for text in CHECKLIST_TEMPLATES.get(label or "", []):
            key = (category, endpoint or "", text)
            if key in seen:
                continue
            seen.add(key)
            items.append(ChecklistItem(category=category, endpoint=endpoint, item=text))

    items.sort(key=lambda i: (i.category, i.endpoint or "", i.item))
    return items
