package rdp

// IsTLSRecord reports whether data begins with a TLS record header
// (content type + version 0x03 0x0n).
func IsTLSRecord(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	switch data[0] {
	case 20, 21, 22, 23: // ChangeCipherSpec, Alert, Handshake, ApplicationData
		return data[1] == 0x03 && data[2] <= 0x04
	default:
		return false
	}
}
