# Recording the ActionScope Demo GIF

To create the terminal GIF shown in the README:

1. Install vhs: https://github.com/charmbracelet/vhs

   ```bash
   brew install charmbracelet/tap/vhs
   ```

2. Create demo.tape:

   ```
   Output demo.gif
   Set Shell "bash"
   Set FontSize 14
   Set Width 900
   Set Height 500

   Type "pip install actionscope" Sleep 500ms Enter
   Sleep 3s
   Type "actionscope scan tests/fixtures/demo_repo" Sleep 500ms Enter
   Sleep 4s
   ```

3. Run:

   ```bash
   vhs demo.tape
   ```

4. Upload demo.gif to the repo and add to README:

   ```markdown
   ![ActionScope Demo](docs/demo.gif)
   ```
