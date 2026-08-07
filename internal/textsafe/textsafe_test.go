package textsafe

import "testing"

func TestHasControl(t *testing.T) {
	if HasControl("safe ASCII") {
		t.Fatal("safe text was rejected")
	}
	for _, value := range []string{"\x00", "\n", "\x1b", "\x7f", "\u0085"} {
		if !HasControl("before" + value + "after") {
			t.Errorf("did not detect %q", value)
		}
	}
}

func TestTerminal(t *testing.T) {
	if got, want := Terminal("a\n\r\t\x00\x1b\u0085z"), `a\n\r\t\x00\x1b\x85z`; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
