// Package textsafe centralizes validation and escaping for untrusted text that
// may be written to a terminal.
package textsafe

import (
	"fmt"
	"strings"
)

// HasControl reports whether value contains a C0, DEL, or C1 control rune.
func HasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r >= 0x7f && r <= 0x9f {
			return true
		}
	}
	return false
}

// Terminal converts control runes to visible ASCII escapes so one value cannot
// create extra lines or terminal control sequences.
func Terminal(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch r {
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 || r >= 0x7f && r <= 0x9f {
				if r <= 0xff {
					fmt.Fprintf(&b, "\\x%02x", r)
				} else {
					fmt.Fprintf(&b, "\\u%04x", r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}
