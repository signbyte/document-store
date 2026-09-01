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
