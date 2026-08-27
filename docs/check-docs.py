#!/usr/bin/env python3
"""check-docs — the two things that silently rot in a Mintlify tree.

1. NAV. Both configs must parse as JSON, every page they name must exist on
   disk, and every page on disk must be named by at least one of them. A page
   in no nav is unreachable; a nav entry with no page is a 404 in the sidebar.
   Neither fails a build.

2. LINKS. Product-page links are extensionless and Mintlify-relative, so a
   typo renders as a working-looking link that 404s only when clicked.

Run from anywhere:  python3 docs/check-docs.py
Exit 0 clean, 1 with findings.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

DOCS = pathlib.Path(__file__).resolve().parent

# Not pages: the directory's own readme, and everything that is an asset or a
# receipt attachment rather than a rendered document.
NOT_PAGES = {"README.md"}
PAGE_SUFFIXES = {".md", ".mdx"}
ASSET_DIRS = {"images"}

LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*$", re.M)


def slug(heading: str) -> str:
    """GitHub/Mintlify heading slug: lowercase, drop punctuation, spaces to '-'."""
    text = re.sub(r"[`*_]", "", heading)
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE).strip().lower()
    return re.sub(r"\s+", "-", text)


def anchors_of(path: pathlib.Path) -> set[str]:
    return {slug(h) for h in HEADING.findall(path.read_text())}


def page_file(source: pathlib.Path, target: str) -> pathlib.Path | None:
    candidate = _base(source, target)
    for suffix in (".mdx", ".md"):
        hit = candidate.with_name(candidate.name + suffix)
        if hit.is_file():
            return hit
    return candidate if candidate.is_file() else None


def nav_pages(config: pathlib.Path) -> set[str]:
    data = json.loads(config.read_text())
    found: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "pages" and isinstance(value, list):
                    found.update(p for p in value if isinstance(p, str))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data.get("navigation", {}))
    return found


def pages_on_disk() -> set[str]:
    out: set[str] = set()
    for path in DOCS.rglob("*"):
        if path.suffix not in PAGE_SUFFIXES or not path.is_file():
            continue
        rel = path.relative_to(DOCS)
        if rel.name in NOT_PAGES or rel.parts[0] in ASSET_DIRS:
            continue
        out.add(str(rel.with_suffix("")))
    return out


def _base(source: pathlib.Path, target: str) -> pathlib.Path:
    root = source.parent if target.startswith(("./", "../")) else DOCS
    return (root / target.lstrip("/")).resolve()


def resolves(source: pathlib.Path, target: str) -> bool:
    """Does an extensionless Mintlify link point at something that exists?

    Mintlify resolves both `/foo` and a bare `foo` against the SITE ROOT, not
    against the linking page's directory — so `kubernetes` written on
    `environments/managed-cloud` is a 404, not a sibling link. Only an
    explicitly relative `./` or `../` prefix walks from the page. Resolving the
    way the renderer does is the whole point of this check.
    """
    candidate = _base(source, target)
    if DOCS not in candidate.parents and candidate != DOCS:
        return False  # escapes the site root: exists in git, 404s on the site
    if candidate.is_dir():
        return True
    for suffix in ("", ".mdx", ".md"):
        if candidate.with_name(candidate.name + suffix).is_file():
            return True
    return False


def main() -> int:
    findings: list[str] = []

    configs = {name: DOCS / name for name in ("docs.json", "docs.public.json")}
    navs: dict[str, set[str]] = {}
    for name, path in configs.items():
        try:
            navs[name] = nav_pages(path)
            print(f"parse   OK  {name} ({len(navs[name])} pages)")
        except Exception as exc:  # noqa: BLE001 — the message is the finding
            findings.append(f"{name}: does not parse — {exc}")

    disk = pages_on_disk()
    print(f"disk    {len(disk)} pages")

    for name, pages in navs.items():
        for page in sorted(pages - disk):
            findings.append(f"{name}: names '{page}', which is not on disk")

    referenced = set().union(*navs.values()) if navs else set()
    for page in sorted(disk - referenced):
        findings.append(f"disk: '{page}' is in no navigation config")

    checked = 0
    for path in sorted(DOCS.rglob("*")):
        if path.suffix not in PAGE_SUFFIXES or not path.is_file():
            continue
        if path.name in NOT_PAGES:
            continue
        for raw in LINK.findall(path.read_text()):
            raw = raw.split()[0]
            if not raw or raw.startswith(("http://", "https://", "mailto:")):
                continue
            target, _, anchor = raw.partition("#")
            checked += 1
            if not target:  # same-page anchor
                if anchor and anchor not in anchors_of(path):
                    findings.append(
                        f"{path.relative_to(DOCS)}: anchor '#{anchor}' has no heading"
                    )
                continue
            if not resolves(path, target):
                findings.append(
                    f"{path.relative_to(DOCS)}: link '{target}' resolves to nothing"
                )
                continue
            if anchor:
                dest = page_file(path, target)
                if dest is not None and anchor not in anchors_of(dest):
                    findings.append(
                        f"{path.relative_to(DOCS)}: '{target}' has no heading "
                        f"matching anchor '#{anchor}'"
                    )
    print(f"links   {checked} internal links checked (anchors included)")

    if findings:
        print()
        for finding in findings:
            print(f"FAIL    {finding}")
        print(f"\n{len(findings)} finding(s)")
        return 1
    print("\nOK — navs consistent, every page reachable, every internal link resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
