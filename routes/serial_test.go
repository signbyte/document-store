package routes

import (
	"fmt"
	"strings"
)

// testSerial returns an eID national identifier the way a Latvian certificate and
// a Latvian person write it — the country code, a six-digit leading group and a
// five-digit serial. It is deliberately NOT the spelling this service stores: the
// grant route reduces it, and the tests below exist to hold it to that.
//
// Assembled from its parts at run time rather than written as a literal: an
// identifier-shaped constant in source is indistinguishable from a credential to a
// secret scanner, and from a real person's code to a reader.
func testSerial(birth, serial int) string {
	return fmt.Sprintf("PNOLV-%06d-%05d", birth, serial)
}

// testSerialStored is the same person in the one spelling this service stores and
// compares: the separators gone.
func testSerialStored(birth, serial int) string {
	return fmt.Sprintf("PNOLV-%06d%05d", birth, serial)
}

var (
	// invitedSerial is the co-signer the workflow service grants below.
	invitedSerial = testSerial(123456, 78900)
	// strangerSerial is never granted: the reads it attempts must fail closed.
	strangerSerial = testSerial(999999, 99999)
)

// grantBodyLowerSpaced spells the grant payload the way a caller might send it —
// lower-cased and space-padded — because the route's match is normalization-aware
// and the test is there to hold it to that.
func grantBodyLowerSpaced(serial string) []byte {
	return []byte(fmt.Sprintf(`{"serial":" %s"}`, strings.ToLower(serial)))
}
