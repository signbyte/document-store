package request

import "testing"

func TestValidPreservationClass(t *testing.T) {
	cases := []struct {
		class string
		want  bool
	}{
		{"", true}, // empty defaults to "none" at the store layer
		{"none", true},
		{"b_lt", true},
		{"preservation", true},
		{"bogus", false},
		{"NONE", false}, // case-sensitive
	}

	for _, c := range cases {
		if got := ValidPreservationClass(c.class); got != c.want {
			t.Errorf("ValidPreservationClass(%q) = %v, want %v", c.class, got, c.want)
		}
	}
}
