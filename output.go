package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type change struct {
	entry  entry
	old    remote
	exists bool
	action string
}

func useColor(out io.Writer) bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := out.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func (a *app) paint(code, text string) string {
	if !a.color {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (a *app) preview(changes []change, dry bool) int {
	title := "ghsecretsync · Sync preview"
	if dry {
		title += " (dry run)"
	}
	fmt.Fprintf(a.out, "\n%s\n", a.paint("1", title))
	fmt.Fprintf(a.out, "Vault: %s  →  %s\n", a.cfg.Vault, a.cfg.Host)
	counts := map[string]int{}
	destination := ""
	for _, c := range changes {
		if c.entry.Target.String() != destination {
			destination = c.entry.Target.String()
			fmt.Fprintf(a.out, "\n%s\n", a.paint("1;36", destination))
		}
		symbol, code := "+", "32"
		if c.action == "update" {
			symbol, code = "~", "33"
		}
		if c.action == "unchanged" {
			symbol, code = "=", "90"
		}
		label := fmt.Sprintf("%s %-9s", symbol, c.action)
		fmt.Fprintf(a.out, "  %s %-8s %s\n", a.paint(code, label), strings.TrimSuffix(c.entry.Kind, "s"), c.entry.Name)
		counts[c.action]++
	}
	fmt.Fprintf(a.out, "\n%d to create · %d to update · %d unchanged\n", counts["create"], counts["update"], counts["unchanged"])
	return counts["create"] + counts["update"]
}

func (a *app) confirm(ctx context.Context) (bool, error) {
	fmt.Fprintf(a.out, "\nApply these changes? [y/N] ")
	if a.in == nil {
		return false, nil
	}
	// Permit Ctrl-C to cancel while waiting for terminal input.
	type answer struct {
		text string
		err  error
	}
	answers := make(chan answer, 1)
	go func() {
		line, err := bufio.NewReader(a.in).ReadString('\n')
		answers <- answer{line, err}
	}()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case result := <-answers:
		if result.err != nil && result.err != io.EOF {
			return false, fmt.Errorf("read confirmation: %w", result.err)
		}
		text := strings.ToLower(strings.TrimSpace(result.text))
		return text == "y" || text == "yes", nil
	}
}
