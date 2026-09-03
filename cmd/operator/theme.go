// Package main — the console's shared Lip Gloss styles (M17-E Session
// 17.6.2, ADR-084 §D-2). One place for every panel's border, color, and
// spacing choices, so panels.go's seven render functions read as pure
// layout logic rather than each re-deriving its own styling.
//
// [REF: ADR-084 D-2; build_M17E.md Phase 17.6 Session 17.6.2]
package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

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

	// legendPadV/legendPadH are the '?' overlay's inner padding. Named
	// because mnd rightly flags bare numbers here: they are layout, and
	// layout constants belong next to the style that uses them.
	legendPadV = 1
	legendPadH = 2

	// legendStyle boxes the '?' overlay distinctly from the seven data
	// panels — a double border marks it as "about the console" rather
	// than "data from the network", so the two are never confused at a
	// glance.
	legendStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(colorAccent).
			Padding(legendPadV, legendPadH).
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
	var border lipgloss.Color
	switch sev {
	case severityAlert:
		border = colorAlert
	case severityWarn:
		border = colorWarn
	case severityOK:
		border = colorOK
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

// ── Progress bars ────────────────────────────────────────────────────────
//
// [Added, Session 18.1.5] Several things this console reports are waits:
// vetting before the first upload can land, a repair rebuilding a shard.
// Reported as bare numbers they read as a frozen screen; reported as a bar
// they read as a system doing work. Both are the same data — the bar is a
// presentation of a real ratio, never an animation running on a timer with
// nothing behind it.

// progressBarWidth is the cell count of every bar in the console. Fixed
// rather than proportional to terminal width: these bars sit inside
// bordered panels laid out side by side, so a bar that grew with the window
// would push its neighbour off the row.
const progressBarWidth = 24

// roundToNearest converts Go's truncating float-to-int conversion into
// round-half-up. Without it a bar at 99.9% would render one cell short of
// full, which reads as "stuck just before done" on the one panel an
// audience watches a clock against.
const roundToNearest = 0.5

// renderProgressBar draws `fraction` (clamped to 0..1) as a filled bar with
// a trailing percentage, coloured by sev.
//
// It uses U+2588 FULL BLOCK and U+2591 LIGHT SHADE, both single-column, so
// the bar's display width equals progressBarWidth exactly — the same
// byte-vs-column trap phoneOrDash documents, avoided here by construction
// rather than by test.
func renderProgressBar(fraction float64, sev severity) string {
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}

	filled := int(fraction*float64(progressBarWidth) + roundToNearest)
	bar := strings.Repeat("\u2588", filled) + strings.Repeat("\u2591", progressBarWidth-filled)

	return statusStyle(sev).Render(bar) + dimStyle.Render(fmt.Sprintf("  %3d%%", int(fraction*percentageScale+roundToNearest)))
}

// renderIndeterminateBar is for work that is genuinely in flight but whose
// completion ratio this console cannot compute — a repair job the admin API
// reports as IN_PROGRESS with no byte counter behind it.
//
// It deliberately does NOT animate. A moving barber-pole would imply
// progress the console cannot actually observe, and the whole point of this
// panel set is that nothing on screen claims more than the data supports.
// A static marked band plus a count says "running, N of them" without
// inventing a percentage.
func renderIndeterminateBar(active int, sev severity) string {
	if active <= 0 {
		return dimStyle.Render(strings.Repeat("\u2591", progressBarWidth) + "  idle")
	}
	marked := active
	if marked > progressBarWidth {
		marked = progressBarWidth
	}
	bar := strings.Repeat("\u2593", marked) + strings.Repeat("\u2591", progressBarWidth-marked)
	return statusStyle(sev).Render(bar) + dimStyle.Render(fmt.Sprintf("  %d running", active))
}
