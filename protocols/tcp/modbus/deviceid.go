// Package modbus builds Modbus PDUs that the modbusone library does not
// implement, currently the Encapsulated Interface Transport (FC 0x2B) Read
// Device Identification reply (MEI type 0x0E, Modbus Application Protocol
// v1.1b3 section 6.21).
package modbus

// Function and MEI codes for Read Device Identification.
const (
	FcEncapsulatedInterface byte = 0x2B
	MEIReadDeviceID         byte = 0x0E
)

// Read Device ID codes.
const (
	ReadDeviceIDBasic      byte = 0x01
	ReadDeviceIDRegular    byte = 0x02
	ReadDeviceIDExtended   byte = 0x03
	ReadDeviceIDIndividual byte = 0x04
)

// Exception codes used by the reply builder.
const (
	ExcIllegalFunction    byte = 0x01
	ExcIllegalDataAddress byte = 0x02
	ExcIllegalDataValue   byte = 0x03
)

// conformityRegular is "regular identification, stream and individual access".
const conformityRegular byte = 0x82

// maxObjectBytes keeps the reply PDU within the 253-byte Modbus limit:
// 7 header bytes (fc, MEI, code, conformity, more follows, next id, count)
// plus objects of 2 header bytes each.
const maxObjectBytes = 253 - 7

// DeviceIdentity holds the basic (0x00-0x02) and regular (0x03-0x06)
// identification objects.
type DeviceIdentity struct {
	VendorName          string
	ProductCode         string
	MajorMinorRevision  string
	VendorURL           string
	ProductName         string
	ModelName           string
	UserApplicationName string
}

// DefaultDeviceIdentity is a Modicon M340 PLC, the identity a real BMX P34
// CPU reports to Read Device Identification.
var DefaultDeviceIdentity = DeviceIdentity{
	VendorName:          "Schneider Electric",
	ProductCode:         "BMX P34 2020",
	MajorMinorRevision:  "v2.70",
	VendorURL:           "http://www.schneider-electric.com",
	ProductName:         "Modicon M340",
	ModelName:           "BMX P34 2020",
	UserApplicationName: "",
}

func (d DeviceIdentity) objects() []string {
	return []string{
		d.VendorName,
		d.ProductCode,
		d.MajorMinorRevision,
		d.VendorURL,
		d.ProductName,
		d.ModelName,
		d.UserApplicationName,
	}
}

// ReadDeviceIDRequest is a parsed FC 0x2B / MEI 0x0E request PDU.
type ReadDeviceIDRequest struct {
	Code     byte
	ObjectID byte
}

// ParseReadDeviceID parses a request PDU (function code first). ok is false
// when the PDU is not a Read Device Identification request.
func ParseReadDeviceID(pdu []byte) (ReadDeviceIDRequest, bool) {
	if len(pdu) < 4 || pdu[0] != FcEncapsulatedInterface || pdu[1] != MEIReadDeviceID {
		return ReadDeviceIDRequest{}, false
	}
	return ReadDeviceIDRequest{Code: pdu[2], ObjectID: pdu[3]}, true
}

// ReadDeviceIDReply builds the response PDU for req. A non-zero exception
// code means the caller should send an exception reply instead.
func ReadDeviceIDReply(req ReadDeviceIDRequest, id DeviceIdentity) ([]byte, byte) {
	objs := id.objects()
	var first, last int // object id range, inclusive
	switch req.Code {
	case ReadDeviceIDBasic:
		first, last = 0x00, 0x02
	case ReadDeviceIDRegular, ReadDeviceIDExtended:
		// No extended objects exist, so extended returns the regular set.
		first, last = 0x00, len(objs)-1
	case ReadDeviceIDIndividual:
		if int(req.ObjectID) >= len(objs) {
			return nil, ExcIllegalDataAddress
		}
		first, last = int(req.ObjectID), int(req.ObjectID)
	default:
		return nil, ExcIllegalDataValue
	}
	// Stream access starts at the requested object; an id outside the
	// category restarts at the first object of the category.
	if req.Code != ReadDeviceIDIndividual && int(req.ObjectID) >= first && int(req.ObjectID) <= last {
		first = int(req.ObjectID)
	}

	pdu := []byte{FcEncapsulatedInterface, MEIReadDeviceID, req.Code, conformityRegular, 0x00, 0x00, 0x00}
	used, count := 0, 0
	for oid := first; oid <= last; oid++ {
		v := objs[oid]
		if len(v) > 0xFF {
			v = v[:0xFF]
		}
		if used+2+len(v) > maxObjectBytes {
			pdu[4] = 0xFF // more follows
			pdu[5] = byte(oid)
			break
		}
		pdu = append(pdu, byte(oid), byte(len(v)))
		pdu = append(pdu, v...)
		used += 2 + len(v)
		count++
	}
	pdu[6] = byte(count)
	return pdu, 0
}
