# ForkSpan — fork / inspect / replay flow (m1)
# Re-render: vhs docs/demo.tape  (writes assets/demo.gif)
Output assets/demo.gif
Set FontSize 14
Set Width 880
Set Height 480
Set Theme "Dracula"

# Build the binary.
Type "go build -o forkspan ./cmd/forkspan"
Enter
Sleep 3s

# Inspect the bundled compromised-agent trace; dump the StateSnapshot at the
# intrusion span and pretty-print it so the blast radius is visible.
Type "./forkspan inspect assets/sample-compromised-trace.json -s 0a0b0c0d0e0f0a0b --json | python3 -m json.tool | head -24"
Enter
Sleep 1s

# The fork primitive (m2 milestone — roadmap pointer in v0.1).
Type "./forkspan fork --span 0a0b0c0d0e0f0a0b --block-tool bash"
Enter
Sleep 1s

# Counterfactual replay + diff (m2/m3 — roadmap pointer in v0.1).
Type "./forkspan replay --branch demo"
Enter
Sleep 2s
