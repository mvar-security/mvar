# Output
Output assets/demo.gif

# Terminal settings
Set Shell "bash"
Set FontSize 13
Set FontFamily "JetBrains Mono"
Set Width 800
Set Height 550
Set Theme "Dracula"
Set WindowBar Colorful
Set BorderRadius 8
Set Padding 20
Set Framerate 24
Set PlaybackSpeed 1.0

# Hidden setup — activate venv and clear screen
Hide
Type "cd /Users/shawncohen/Documents/mirra_project/MIRRA_LLM_BRIDGE_v1/mvar"
Enter
Type "source .venv_313/bin/activate"
Enter
Type "clear"
Enter
Show

Sleep 500ms

# Type the command visibly
Type "python3 /tmp/mvar_demo_animated.py"
Sleep 600ms
Enter
Sleep 1200ms

# Animated wrapper controls line-by-line output timing
# Total wrapper runtime is approximately 38 seconds
# Add buffer for safety
Sleep 45s

# Hold on final result before loop
Sleep 4s
