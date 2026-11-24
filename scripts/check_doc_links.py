"""Check local links, images, and heading references in the project's guides."""

import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class HTMLLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attribute = {"a": "href", "img": "src"}.get(tag)
        target = dict(attrs).get(attribute)
        if target:
            self.links.append(target)


def read_guide(path):
    anchors, links = set(), []
    fence = ""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        marker = re.match(r" {0,3}(`{3,}|~{3,})", line)
        if fence:
            if marker and marker[1].startswith(fence) and not line[marker.end():].strip():
                fence = ""
            continue
        if marker:
            fence = marker[1]
            continue
        if heading := re.match(r"^#{1,6}\s+(.+?)\s*$", line):
            stem = re.sub(r"[^\w -]", "", heading[1].lower()).replace(" ", "-")
            anchor = stem
            suffix = 0
            while anchor in anchors:
                suffix += 1
                anchor = f"{stem}-{suffix}"
            anchors.add(anchor)
        line = re.sub(r"(`+).*?\1", "", line)
        html = HTMLLinks()
        html.feed(line)
        # Each closing bracket matches separately, including a linked image.
        targets = re.findall(r"\]\((<[^>]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\)", line)
        links.extend((number, target.strip("<>")) for target in targets + html.links)
    return anchors, links


def check(root):
    root = root.resolve()
    files = [root / "README.md", root / "SECURITY.md", *sorted((root / "docs").glob("*.md"))]
    guides = {}
    errors = []
    for path in files:
        if not path.resolve().is_relative_to(root):
            errors.append(f"{path.relative_to(root)}: guide resolves outside the checkout")
            continue
        guides[path] = read_guide(path)
    count = 0
    for source, (_, links) in guides.items():
        for line, link in links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            count += 1
            path = (source.parent / unquote(url.path)).resolve() if url.path else source
            if not path.is_relative_to(root) or not path.exists():
                errors.append(f"{source.relative_to(root)}:{line}: missing local target {link}")
            elif path in guides and url.fragment and unquote(url.fragment) not in guides[path][0]:
                errors.append(f"{source.relative_to(root)}:{line}: missing heading {link}")
    return count, errors


if __name__ == "__main__":
    count, errors = check(Path(__file__).resolve().parents[1])
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Checked {count} relative references in the project guides.")
    sys.exit(bool(errors))
