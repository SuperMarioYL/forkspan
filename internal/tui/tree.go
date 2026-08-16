package tui

import (
	"fmt"
	"strings"

	"github.com/SuperMarioYL/forkspan/internal/fork"
	"github.com/SuperMarioYL/forkspan/internal/ingest"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// node is a flattened tree row (DFS preorder) carrying its indentation depth.
type node struct {
	span  ingest.Span
	depth int
}

// model is the bubbletea model for the recorded-span navigator.
type model struct {
	tree     *ingest.Tree
	rows     []node
	cursor   int
	markedID string // operator's live mark (the fork point)
	preMark  string // intrusion span pre-marked in the sample trace
	flash    string // last action feedback
	width    int
	height   int
}

var (
	styleTitle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#5E5CE6"))
	styleCursor   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0071E3"))
	styleIntrusion = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#BF5AF2"))
	styleMark     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF9F0A"))
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("#6E6E73"))
	styleTool     = lipgloss.NewStyle().Foreground(lipgloss.Color("#10A37F"))
)

func newModel(tree *ingest.Tree, preMark string) *model {
	m := &model{tree: tree, markedID: preMark, preMark: preMark}
	m.flatten()
	if len(m.rows) > 0 {
		// Land the cursor on the pre-marked intrusion span when present.
		if preMark != "" {
			for i, r := range m.rows {
				if r.span.SpanID == preMark {
					m.cursor = i
					break
				}
			}
		}
	}
	return m
}

// flattenTree produces a DFS-preorder list of the tree with indentation
// depths. A `seen` set guards the DFS against a cyclic ParentID (a malformed /
// compromised-agent trace) so the walk never recurses forever — mirrors
// diff.Subgraph's cycle guard. Shared by the interactive navigator model and
// the non-interactive RenderTree helper so the printed tree matches the TUI.
func flattenTree(tree *ingest.Tree) []node {
	seen := map[string]bool{}
	var rows []node
	var walk func(id string, depth int)
	walk = func(id string, depth int) {
		s := tree.Get(id)
		if s == nil {
			return
		}
		rows = append(rows, node{span: *s, depth: depth})
		for _, cid := range tree.Children(id) {
			if seen[cid] {
				continue
			}
			seen[cid] = true
			walk(cid, depth+1)
		}
	}
	for _, root := range tree.Roots() {
		if seen[root] {
			continue
		}
		seen[root] = true
		walk(root, 0)
	}
	return rows
}

// flatten refreshes the model's rows via the shared DFS flatten + cycle guard.
func (m *model) flatten() {
	m.rows = flattenTree(m.tree)
}

// Init is bubbletea's initial command (none).
func (m *model) Init() tea.Cmd { return nil }

// Update handles navigation and the mark/snapshot actions.
func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		switch {
		case msg.Type == tea.KeyCtrlC, msg.Type == tea.KeyEsc:
			m.flash = "quit"
			return m, tea.Quit
		case msg.String() == "q":
			m.flash = "quit"
			return m, tea.Quit
		case msg.String() == "j", msg.Type == tea.KeyDown:
			if m.cursor < len(m.rows)-1 {
				m.cursor++
			}
			m.flash = ""
		case msg.String() == "k", msg.Type == tea.KeyUp:
			if m.cursor > 0 {
				m.cursor--
			}
			m.flash = ""
		case msg.String() == "m":
			if len(m.rows) > 0 {
				m.markedID = m.rows[m.cursor].span.SpanID
				m.flash = fmt.Sprintf("marked intrusion span %s — press s to fork the StateSnapshot", short(m.markedID))
			}
		case msg.String() == "s":
			if len(m.rows) == 0 {
				m.flash = "no spans to snapshot"
				break
			}
			at := m.markedID
			if at == "" {
				at = m.rows[m.cursor].span.SpanID
			}
			snap, err := fork.Snapshot(m.tree, at)
			if err != nil {
				m.flash = "snapshot: " + err.Error()
				break
			}
			b, _ := snap.MarshalJSON()
			const out = "forkspan-snapshot.json"
			if err := writeFile(out, b); err != nil {
				m.flash = "snapshot write: " + err.Error()
				break
			}
			m.flash = fmt.Sprintf("forked StateSnapshot at %s → %s (%d reached spans, %d reachable tool calls)",
				short(at), out, len(snap.ReachedSpans), len(snap.ReachableToolCalls))
		case msg.String() == "d":
			m.flash = "diff view is the m2 milestone — see roadmap"
		}
	}
	return m, nil
}

// View renders the navigator.
func (m *model) View() string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("ForkSpan — recorded span tree") + "\n")
	b.WriteString(styleDim.Render("j/k navigate · m mark intrusion · s fork StateSnapshot · d diff(m2) · q quit") + "\n\n")

	for i, r := range m.rows {
		prefix := strings.Repeat("  ", r.depth)
		marker := "  "
		switch {
		case r.span.SpanID == m.markedID && r.span.Intrusion:
			marker = "▶!"
		case r.span.SpanID == m.markedID:
			marker = "▶ "
		case r.span.Intrusion:
			marker = "! "
		}
		line := fmt.Sprintf("%s%s%s  %s  %s",
			prefix, marker, roleTag(r.span.Role), r.span.Name, short(r.span.SpanID))
		if r.span.IsToolCall() && r.span.ToolName != "" {
			line += "  " + styleTool.Render("["+r.span.ToolName+"]")
		}
		if i == m.cursor {
			line = styleCursor.Render("▸ " + strings.TrimSpace(line))
		}
		b.WriteString(line + "\n")
	}

	if m.flash != "" {
		b.WriteString("\n" + styleMark.Render(m.flash) + "\n")
	}
	return b.String()
}

func roleTag(r ingest.GenAIRole) string {
	switch r {
	case ingest.RoleAgent:
		return "[Agent]"
	case ingest.RoleLLM:
		return "[LLM]  "
	case ingest.RoleTool:
		return "[Tool] "
	default:
		return "[span] "
	}
}

func short(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
