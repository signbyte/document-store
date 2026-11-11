package routes

import (
	"github.com/gmb-lib/go-authbyte/permissions"
)

// The scope group and its levels. A route names the level it requires with one of
// these constants, and the same constants make up what the service declares to a
// membership register, so the two cannot drift apart.
const (
	// ScopeGroup is the scope group every level below belongs to.
	ScopeGroup = "documents"

	// LevelRead covers metadata, content, digest and listing.
	LevelRead = "read"
	// LevelWrite covers ingest, completion, assembly, adding a signature, storing a
	// signed form and deleting.
	LevelWrite = "write"
	// LevelGrant covers giving an invited participant standing access to a chain.
	LevelGrant = "grant"
	// LevelDurable covers storing a document that no retention clock of the
	// service's own removes.
	LevelDurable = "durable"
)

const (
	// ServiceKey is the key the service declares itself under.
	ServiceKey = "document-store"
	// ServiceDisplayName is the name the service declares for itself.
	ServiceDisplayName = "Document storage"
)

// declared is built when the package loads, so a declaration that the library
// refuses stops the program at load rather than at the first start that sends it.
var declared = mustDeclare()

func mustDeclare() *permissions.Set {
	set, err := permissions.New(ServiceKey, ServiceDisplayName)
	if err != nil {
		panic(err)
	}

	err = set.AddLevels(
		permissions.Rung{
			Group:       ScopeGroup,
			Level:       LevelRead,
			Description: "Read a document's metadata, content and digest, and list documents.",
		},
		permissions.Rung{
			Group:       ScopeGroup,
			Level:       LevelWrite,
			Description: "Ingest, complete, assemble, add signatures to, store signed forms of and delete documents.",
		},
		permissions.Rung{
			Group:       ScopeGroup,
			Level:       LevelGrant,
			Description: "Give an invited co-signer standing read and co-sign access to a document's chain.",
		},
		permissions.Rung{
			Group:       ScopeGroup,
			Level:       LevelDurable,
			Description: "Store a document under its product's ownership with no retention window of the service's own.",
		},
	)
	if err != nil {
		panic(err)
	}

	return set
}

// Declared answers what the service declares to a membership register: its
// service key, its display name and the levels of the scope group its routes
// check. It declares no permissions.
func Declared() []*permissions.Set {
	return []*permissions.Set{declared}
}
