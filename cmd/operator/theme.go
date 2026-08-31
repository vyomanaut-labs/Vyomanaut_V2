// Package main — the console's shared Lip Gloss styles (M17-E Session
// 17.6.2, ADR-084 §D-2). One place for every panel's border, color, and
// spacing choices, so panels.go's seven render functions read as pure
// layout logic rather than each re-deriving its own styling.
//
// [REF: ADR-084 D-2; build_M17E.md Phase 17.6 Session 17.6.2]
package main

import "github.com/charmbracelet/lipgloss"

const (
	colorOK      = lipgloss.Color("42")  // green — satisfied / healthy
	colorWarn    = lipgloss.Color("214") // amber — approaching a threshold
	colorAlert   = lipgloss.Color("196") // red — unsatisfied / at cap / overdue
	colorDim     = lipgloss.Color("240") // muted gray — secondary text
	colorAccent  = lipgloss.Color("39")  // blue — headings, panel titles
	panelPadding = 1
)

var (
	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorDim).
			Padding(0, panelPadding).
			MarginRight(1).
			MarginBottom(1)

	panelTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent)

	okStyle    = lipgloss.NewStyle().Foreground(colorOK)
	warnStyle  = lipgloss.NewStyle().Foreground(colorWarn).Bold(true)
	alertStyle = lipgloss.NewStyle().Foreground(colorAlert).Bold(true)
	dimStyle   = lipgloss.NewStyle().Foreground(colorDim)

	headerBarStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("230")).
			Background(colorAccent).
			Padding(0, 1).
			MarginBottom(1)

	// footerStyle renders the keybinding hint bar. Not bold, not colored
	// like a warning — it's navigation, not a status the audience should
	// read as meaningful.
	footerStyle = lipgloss.NewStyle().Foreground(colorDim)

	// legendStyle boxes the '?' overlay distinctly from the seven data
	// panels — a double border marks it as "about the console" rather
	// than "data from the network", so the two are never confused at a
	// glance.
	legendStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(colorAccent).
			Padding(1, 2).
			MarginBottom(1)
)

// statusStyle picks ok/warn/alert by a simple three-way severity, so panel
// code says statusStyle(severity).Render(text) instead of re-deriving the
// same if/else at every call site.
type severity int

const (
	severityOK severity = iota
	severityWarn
	severityAlert
)

func statusStyle(s severity) lipgloss.Style {
	switch s {
	case severityAlert:
		return alertStyle
	case severityWarn:
		return warnStyle
	case severityOK:
		return okStyle
	}
	panic("unreachable: unknown severity")
}

// wrapPanel renders a panel with its title, body, and a border colored by
// sev — the panel's own worst/overall condition, computed by its caller.
// This is the one place severity becomes a border color, so panels.go's
// seven render functions never duplicate the color choice.
//
// [Added, Session 18.1.3] Panels previously shared one uniform, dim border
// regardless of content — a healthy fleet and one with an OVERDUE provider
// looked identical from across a room. Borders now carry the same signal
// the text inside them already did, readable before anyone reads a number.
func wrapPanel(title, body string, sev severity) string {
	border := colorOK
	switch sev {
	case severityAlert:
		border = colorAlert
	case severityWarn:
		border = colorWarn
	}
	return panelStyle.BorderForeground(border).Render(panelTitleStyle.Render(title) + "\n" + body)
}

// wrapPanelNeutral is wrapPanel for panels with no pass/fail condition of
// their own (the event feed, escrow's placeholder figures, the repair
// queue's counts) — coloring these OK/red/amber would fabricate a health
// signal the panel doesn't actually carry. They get the same accent border
// as everything else in the console, just not tied to a severity.
func wrapPanelNeutral(title, body string) string {
	return panelStyle.BorderForeground(colorAccent).Render(panelTitleStyle.Render(title) + "\n" + body)
}
