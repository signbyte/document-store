package documentstore

import (
	"strings"
	"testing"

	"azugo.io/azugo"

	"github.com/gmb-lib/go-authbyte/permissions"
)

// An address nothing listens on.
const nothingListens = "http://127.0.0.1:1"

func membershipSet(t *testing.T) *permissions.Set {
	t.Helper()

	set, err := permissions.New("example-service", "Example service")
	if err != nil {
		t.Fatal(err)
	}

	return set
}

// The membership register's two settings reach the configuration from the
// environment.
func TestTheMembershipRegisterSettingsAreReadFromTheEnvironment(t *testing.T) {
	t.Setenv("MEMBERSHIP_URL", "http://membership.local")
	t.Setenv("MEMBERSHIP_AUDIENCE", "register-audience")

	c := bound(t)
	if c.MembershipURL != "http://membership.local" {
		t.Fatalf("membership URL = %q, want the environment value", c.MembershipURL)
	}
	if c.MembershipAudience != "register-audience" {
		t.Fatalf("membership audience = %q, want the environment value", c.MembershipAudience)
	}
	if !c.MembershipEnabled() {
		t.Fatal("MembershipEnabled() = false with MEMBERSHIP_URL set")
	}
}

// Unset, the register is off and nothing is asked of the deployment.
func TestTheMembershipRegisterIsOffByDefault(t *testing.T) {
	c := bound(t)
	if c.MembershipEnabled() || c.MembershipURL != "" || c.MembershipAudience != "" {
		t.Fatalf("membership settings are not empty by default: %q %q", c.MembershipURL, c.MembershipAudience)
	}
	if err := c.validateMembership(); err != nil {
		t.Fatalf("validateMembership() with no register = %v, want nil", err)
	}
}

func TestAMembershipAddressWithoutAnAudienceIsRefused(t *testing.T) {
	t.Setenv("MEMBERSHIP_URL", "http://membership.local")
	t.Setenv("SERVICE_CLIENT_SECRET", "a-secret")

	err := bound(t).validateMembership()
	if err == nil || !strings.Contains(err.Error(), "MEMBERSHIP_AUDIENCE") {
		t.Fatalf("validateMembership() = %v, want a refusal naming MEMBERSHIP_AUDIENCE", err)
	}
}

func TestAMembershipAddressWithoutAClientSecretIsRefused(t *testing.T) {
	t.Setenv("MEMBERSHIP_URL", "http://membership.local")
	t.Setenv("MEMBERSHIP_AUDIENCE", "register-audience")

	err := bound(t).validateMembership()
	if err == nil || !strings.Contains(err.Error(), "SERVICE_CLIENT_SECRET") {
		t.Fatalf("validateMembership() = %v, want a refusal naming SERVICE_CLIENT_SECRET", err)
	}
}

func TestAMembershipAddressWithBothSettingsIsAccepted(t *testing.T) {
	t.Setenv("MEMBERSHIP_URL", "http://membership.local")
	t.Setenv("MEMBERSHIP_AUDIENCE", "register-audience")
	t.Setenv("SERVICE_CLIENT_SECRET", "a-secret")

	if err := bound(t).validateMembership(); err != nil {
		t.Fatalf("validateMembership() = %v, want nil", err)
	}
}

// The refusals stop the start, not only the check: the whole configuration's
// validation runs them.
func TestAMisconfiguredMembershipRegisterStopsTheStart(t *testing.T) {
	t.Setenv("METRICS_ENABLED", "false")
	t.Setenv("SERVICE_NAME", "document-store")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("AUTH_ISSUER_URL", nothingListens)
	t.Setenv("SERVICE_AUDIENCE", "svc:document")
	t.Setenv("MEMBERSHIP_URL", nothingListens)

	if _, err := New(nil, "0.0.0-test"); err == nil || !strings.Contains(err.Error(), "MEMBERSHIP_AUDIENCE") {
		t.Fatalf("New() = %v, want a refusal naming MEMBERSHIP_AUDIENCE", err)
	}
}

func setMembershipEnv(t *testing.T) {
	t.Helper()

	t.Setenv("MEMBERSHIP_URL", nothingListens)
	t.Setenv("MEMBERSHIP_AUDIENCE", "register-audience")
	t.Setenv("SERVICE_CLIENT_SECRET", "a-secret")
	t.Setenv("AUDIT_ISSUER_URL", nothingListens)
}

// Which of the two uses builds the one outbound client, and which adds the task.
func TestTheOutboundClientAndTheDeclarationTaskFollowTheConfiguration(t *testing.T) {
	cases := []struct {
		name       string
		audit      bool
		membership bool
		wantClient bool
		wantTask   bool
	}{
		{"neither", false, false, false, false},
		{"the access audit only", true, false, true, false},
		{"the membership register only", false, true, true, true},
		{"both", true, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.audit {
				t.Setenv("ACCESS_AUDIT_URL", nothingListens)
			}
			if tc.membership {
				setMembershipEnv(t)
			}

			app := TestApp(t)
			if err := app.DeclareTo(membershipSet(t)); err != nil {
				t.Fatalf("DeclareTo() = %v", err)
			}

			if got := app.outboundClient != nil; got != tc.wantClient {
				t.Fatalf("outbound client present = %v, want %v", got, tc.wantClient)
			}
			if got := app.declaration != nil; got != tc.wantTask {
				t.Fatalf("declaration task present = %v, want %v", got, tc.wantTask)
			}
			if got := app.gdprAudit != nil; got != tc.audit {
				t.Fatalf("access audit client present = %v, want %v", got, tc.audit)
			}
		})
	}
}

// With a register that cannot be reached the service starts and stops as before:
// the declaration is tried in the background and never holds the start.
func TestTheServiceStartsWhileTheMembershipRegisterIsUnreachable(t *testing.T) {
	setMembershipEnv(t)

	app := TestApp(t)
	if err := app.DeclareTo(membershipSet(t)); err != nil {
		t.Fatalf("DeclareTo() = %v", err)
	}
	if app.declaration == nil {
		t.Fatal("the declaration task was not added")
	}

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	ta.Stop()
}
