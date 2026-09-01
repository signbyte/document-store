package documentstore

import "testing"

func TestNewAccessAuditPosterBuildsURL(t *testing.T) {
	cases := []struct {
		name string
		base string
		want string
	}{
		{"no trailing slash", "http://access-audit.local", "http://access-audit.local/v1/access-records"},
		{"trailing slash trimmed", "http://access-audit.local/", "http://access-audit.local/v1/access-records"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newAccessAuditPoster(nil, c.base, "svc:access-audit", "access-audit:write")
			if p.url != c.want {
				t.Fatalf("url = %q, want %q", p.url, c.want)
			}
			if p.audience != "svc:access-audit" || p.scope != "access-audit:write" {
				t.Fatalf("audience/scope not preserved: %+v", p)
			}
		})
	}
}
