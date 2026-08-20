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
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent).
			MarginBottom(1)

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
			Padding(0, 1)
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
	default:
		return okStyle
	}
}
