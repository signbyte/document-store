// Package request holds the document-store HTTP request validation helpers. Most
// inputs are multipart uploads (read in the handlers); this package validates the
// small structured form fields.
package request

// ValidPreservationClasses are the accepted preservation_class values. Empty
// defaults to "none" at the store layer.
var ValidPreservationClasses = map[string]bool{
	"none":         true,
	"b_lt":         true,
	"preservation": true,
}

// ValidPreservationClass reports whether class is an accepted value (empty is
// accepted — it defaults to "none").
func ValidPreservationClass(class string) bool {
	if class == "" {
		return true
	}

	return ValidPreservationClasses[class]
}

// ValidRetentionClasses are the accepted retention_class values: who decides when
// the document goes. Empty defaults to "ttl" at the store layer, which is what
// every document stored so far carries.
var ValidRetentionClasses = map[string]bool{
	"ttl":     true,
	"durable": true,
}

// ValidRetentionClass reports whether class is an accepted value (empty is
// accepted — it defaults to "ttl").
func ValidRetentionClass(class string) bool {
	if class == "" {
		return true
	}

	return ValidRetentionClasses[class]
}
