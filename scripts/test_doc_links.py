import tempfile
import unittest
from pathlib import Path

from check_doc_links import check


class GuideLinksTest(unittest.TestCase):
    def test_markdown_and_html_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docs = root / "docs"
            docs.mkdir()
            (root / "SECURITY.md").write_text("# Security\n")
            guide = docs / "guide.md"
            guide.write_text("# How to recover?\n\n## Next\n\n## Next\n")
            (docs / "preview.jpg").touch()
            (root / "README.md").write_text(
                "[Guide](docs/guide.md#how-to-recover)\n"
                "[![Preview](docs/preview.jpg)](docs/guide.md?raw=true)\n"
                '<a href="docs/guide.md#next-1"><img src="docs/preview.jpg"></a>\n'
                "`[sample](missing)`\n"
                "```sh\n[example](missing)\n```\n"
                "[External](https://example.invalid)\n"
            )
            self.assertEqual(check(root), (5, []))
            guide.write_text("# Guide\n")
            (docs / "preview.jpg").unlink()
            _, errors = check(root)
            self.assertEqual(len(errors), 4)
            self.assertIn("README.md:1: missing heading docs/guide.md#how-to-recover", errors)
            self.assertIn("README.md:2: missing local target docs/preview.jpg", errors)
            self.assertIn("README.md:3: missing heading docs/guide.md#next-1", errors)
            self.assertIn("README.md:3: missing local target docs/preview.jpg", errors)


if __name__ == "__main__":
    unittest.main()
