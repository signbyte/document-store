package store

import (
	"fmt"
	"strings"
)

// testSerial returns an eID national identifier in the PNO form this service
// stores: the country code, a six-digit date-of-birth part and a five-digit
// serial, assembled from those parts at run time rather than written as a
// literal. An identifier-shaped constant in source is indistinguishable from a
// credential to a secret scanner, and from a real person's code to a reader.
func testSerial(birth, serial int) string {
	return fmt.Sprintf("PNOLV-%06d-%05d", birth, serial)
}

var (
	// invitedSerial is the co-signer granted on the chain root below.
	invitedSerial = testSerial(123456, 78900)
	// strangerSerial and ungrantedSerial are never granted: every read they
	// attempt must fail closed.
	strangerSerial  = testSerial(999999, 99999)
	ungrantedSerial = testSerial(0, 0)
)

// lowerTrailingSpace and leadingSpace spell a serial the way a caller might
// actually present it. The stored match is normalization-aware, and these keep
// that visible in the tests instead of implied by a padded literal.
func lowerTrailingSpace(s string) string { return strings.ToLower(s) + " " }
func leadingSpace(s string) string       { return " " + s }
