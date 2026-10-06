# Corpus scan example

`manifest.csv` pins five fixture projects inside this repository to the
v0.5.0 release commit. Run it with:

```bash
actionscope corpus scan examples/corpus/manifest.csv --output-dir corpus-example/
```

The run fetches the commit from GitHub once per entry, so it needs network
access. Expect six credential bindings: five linked to IAM policies in their
project and one literal role whose policy is not in the repository. The
fixtures were written to exercise the scanner, so their match rate says nothing
about real repositories.

See [Corpus Scans](../../docs/corpus.md) for the manifest format, the output
tables, and how anonymization works.
