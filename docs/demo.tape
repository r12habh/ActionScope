# ActionScope 60-second demo recording script for `vhs` (charm.sh).
#
# PREREQUISITES (run once before invoking vhs):
#   1. Install vhs:           brew install vhs
#                             (or see https://github.com/charmbracelet/vhs)
#   2. Install ActionScope in the env vhs will record from:
#                             pip install -e .
#
# This tape intentionally does NOT include the `pip install` step in the
# recording. Installing inside the tape is non-deterministic — on a cold
# pip cache the install can run for 10-30 seconds and there is no vhs
# primitive to wait for a shell prompt, so a fixed `Sleep` either makes
# the recording artificially slow or risks typing the next command
# before pip finishes. The README already shows the install command
# above the GIF; the GIF's job is to show *what running the tool looks
# like*, not to re-cover installation.
#
# Generate the demo GIF (from the repo root):
#   vhs docs/demo.tape
#
# Output is written to docs/demo.gif. Drop it into the README hero by
# replacing the "<!-- Demo GIF placeholder ... -->" comment in README.md.
#
# The recording targets the bundled `tests/fixtures/coverage_repo`
# fixture so the output is reproducible, scary, and self-contained — no
# external repo dependency, no network calls.

Output docs/demo.gif

Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1200
Set Height 800
Set Padding 18
Set TypingSpeed 30ms
Set PlaybackSpeed 1.0

# Visual reminder for viewers (this is a comment, bash treats it as no-op).
Type "# install once:  pip install actionscope" Sleep 400ms Enter
Sleep 800ms

# Frame 1 — scan a real fixture
Type "actionscope scan tests/fixtures/coverage_repo" Sleep 600ms Enter
Sleep 6500ms

# Frame 2 — show that JSON / SARIF output exists too
Type "actionscope scan tests/fixtures/coverage_repo --output-format sarif --output-file results.sarif" Sleep 400ms Enter
Sleep 1500ms

# Frame 3 — confirm SARIF is valid + has rules
Type "head -3 results.sarif" Sleep 400ms Enter
Sleep 2000ms

# Hold the final frame so viewers can read the last screen
Sleep 3000ms
