package routes

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
