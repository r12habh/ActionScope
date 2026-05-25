# ActionScope 60-second demo recording script for `vhs` (charm.sh).
#
# Install vhs once: brew install vhs   (or see https://github.com/charmbracelet/vhs)
#
# Generate the demo GIF:
#   cd <repo root>
#   pip install -e .
#   vhs docs/demo.tape
#
# Output is written to docs/demo.gif. Drop it into the README hero
# (replace the "<!-- Demo GIF placeholder ... -->" comment in README.md).
#
# The recording targets the bundled `tests/fixtures/coverage_repo`
# fixture so the output is reproducible, scary, and self-contained — no
# external repo dependency.

Output docs/demo.gif

Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1200
Set Height 800
Set Padding 18
Set TypingSpeed 30ms
Set PlaybackSpeed 1.0

# Frame 1 — install
Type "pip install actionscope" Sleep 600ms Enter
Sleep 1500ms

# Frame 2 — scan a real fixture
Type "actionscope scan tests/fixtures/coverage_repo" Sleep 600ms Enter
Sleep 6500ms

# Frame 3 — show that JSON / SARIF output exists too
Type "actionscope scan tests/fixtures/coverage_repo --output-format sarif --output-file results.sarif" Sleep 400ms Enter
Sleep 1500ms

# Frame 4 — confirm SARIF is valid + has rules
Type "head -3 results.sarif" Sleep 400ms Enter
Sleep 2000ms

# Hold the final frame so viewers can read the last screen
Sleep 3000ms
