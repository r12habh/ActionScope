# vhs tape for the ActionScope blast-radius demo GIF.
# Render with:  vhs examples/aws-blast-radius-demo/demo.tape
# Produces:     examples/aws-blast-radius-demo/demo.gif

Output examples/aws-blast-radius-demo/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1100
Set Height 900
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 45ms

# Put the local actionscope on PATH without showing the venv plumbing.
Hide
Type "export PATH=$PWD/.venv/bin:$PATH && clear"
Enter
Show

# Beat 1: the workflow only says it assumes a role.
Type "# The workflow just says it assumes an AWS role:"
Enter
Sleep 600ms
Type "grep role-to-assume examples/aws-blast-radius-demo/.github/workflows/deploy.yml"
Enter
Sleep 1800ms

Type "# But what can that role actually DO if CI is compromised?"
Enter
Sleep 900ms

# Beat 2: ActionScope answers it. Trim to the blast-radius reveal so the GIF
# ends held on the punchline (the role's actual AWS power), not the scroll tail.
Type "actionscope scan examples/aws-blast-radius-demo --no-color | sed -n '1,28p'"
Enter
Sleep 4500ms

# Hold on the blast-radius table.
Sleep 3500ms
