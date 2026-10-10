package dicom

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Data set (identifier) parsing and encoding for C-FIND/C-GET/C-MOVE
// (PS3.5 section 7). Only the little endian transfer syntaxes are handled;
// sequence contents are skipped.

const (
	ExplicitVRBigEndian            = "1.2.840.10008.1.2.2"
	DeflatedExplicitVRLittleEndian = "1.2.840.10008.1.2.1.99"

	// maxElements bounds the top-level elements decoded from one identifier.
	maxElements = 64
	// maxDepth bounds sequence nesting.
	maxDepth = 4
	// maxQueryValue bounds one rendered value in QueryMap.
	maxQueryValue = 256

	undefinedLength = 0xFFFFFFFF
)

var ErrUnsupportedTransferSyntax = errors.New("unsupported DICOM transfer syntax")

// Tag is a (group, element) pair packed as group<<16 | element.
type Tag uint32

const (
	tagItem      Tag = 0xFFFEE000
	tagItemDelim Tag = 0xFFFEE00D
	tagSeqDelim  Tag = 0xFFFEE0DD
)

func (t Tag) String() string {
	return fmt.Sprintf("(%04X,%04X)", uint16(t>>16), uint16(t))
}

// Element is one top-level data element. Sequences carry VR "SQ" and no value.
type Element struct {
	Tag   Tag
	VR    string
	Value []byte
}

type dictEntry struct {
	keyword string
	vr      string
}

// Attributes commonly seen in Q/R and worklist identifiers (PS3.6).
var dictionary = map[Tag]dictEntry{
	0x00080005: {"SpecificCharacterSet", "CS"},
	0x00080016: {"SOPClassUID", "UI"},
	0x00080018: {"SOPInstanceUID", "UI"},
	0x00080020: {"StudyDate", "DA"},
	0x00080021: {"SeriesDate", "DA"},
	0x00080030: {"StudyTime", "TM"},
	0x00080031: {"SeriesTime", "TM"},
	0x00080050: {"AccessionNumber", "SH"},
	0x00080052: {"QueryRetrieveLevel", "CS"},
	0x00080054: {"RetrieveAETitle", "AE"},
	0x00080056: {"InstanceAvailability", "CS"},
	0x00080060: {"Modality", "CS"},
	0x00080061: {"ModalitiesInStudy", "CS"},
	0x00080080: {"InstitutionName", "LO"},
	0x00080090: {"ReferringPhysicianName", "PN"},
	0x00081030: {"StudyDescription", "LO"},
	0x0008103E: {"SeriesDescription", "LO"},
	0x00100010: {"PatientName", "PN"},
	0x00100020: {"PatientID", "LO"},
	0x00100021: {"IssuerOfPatientID", "LO"},
	0x00100030: {"PatientBirthDate", "DA"},
	0x00100040: {"PatientSex", "CS"},
	0x00101010: {"PatientAge", "AS"},
	0x0020000D: {"StudyInstanceUID", "UI"},
	0x0020000E: {"SeriesInstanceUID", "UI"},
	0x00200010: {"StudyID", "SH"},
	0x00200011: {"SeriesNumber", "IS"},
	0x00200013: {"InstanceNumber", "IS"},
	0x00201200: {"NumberOfPatientRelatedStudies", "IS"},
	0x00201206: {"NumberOfStudyRelatedSeries", "IS"},
	0x00201208: {"NumberOfStudyRelatedInstances", "IS"},
	0x00201209: {"NumberOfSeriesRelatedInstances", "IS"},
	0x00321060: {"RequestedProcedureDescription", "LO"},
	0x00400001: {"ScheduledStationAETitle", "AE"},
	0x00400002: {"ScheduledProcedureStepStartDate", "DA"},
	0x00400003: {"ScheduledProcedureStepStartTime", "TM"},
	0x00400100: {"ScheduledProcedureStepSequence", "SQ"},
	0x00401001: {"RequestedProcedureID", "SH"},
}

// Keyword returns the PS3.6 keyword of a tag, or "(gggg,eeee)" if unknown.
func Keyword(t Tag) string {
	if e, ok := dictionary[t]; ok {
		return e.keyword
	}
	return t.String()
}

func dictVR(t Tag) string {
	if e, ok := dictionary[t]; ok {
		return e.vr
	}
	return ""
}

// longVR reports whether an explicit VR uses the 2 reserved bytes + 4-byte length form.
func longVR(vr string) bool {
	switch vr {
	case "OB", "OD", "OF", "OL", "OV", "OW", "SQ", "SV", "UC", "UN", "UR", "UT", "UV":
		return true
	}
	return false
}

func binaryVR(vr string) bool {
	switch vr {
	case "AT", "FL", "FD", "OB", "OD", "OF", "OL", "OV", "OW", "SL", "SS", "SV", "UL", "UN", "US", "UV":
		return true
	}
	return false
}

func explicitVR(transferSyntax string) (bool, error) {
	switch transferSyntax {
	case ImplicitVRLittleEndian:
		return false, nil
	case ExplicitVRBigEndian, DeflatedExplicitVRLittleEndian:
		return false, ErrUnsupportedTransferSyntax
	}
	// every other standard transfer syntax encodes the data set as Explicit VR LE
	return true, nil
}

type dsParser struct {
	b        []byte
	explicit bool
}

func (p *dsParser) tag() (Tag, bool) {
	if len(p.b) < 4 {
		return 0, false
	}
	return Tag(uint32(binary.LittleEndian.Uint16(p.b[0:2]))<<16 | uint32(binary.LittleEndian.Uint16(p.b[2:4]))), true
}

// next decodes one element header and value at the current position.
func (p *dsParser) next(depth int) (Element, error) {
	t, ok := p.tag()
	if !ok || t>>16 == 0xFFFE {
		return Element{}, ErrMalformed
	}
	e := Element{Tag: t}
	var length uint32
	if p.explicit {
		if len(p.b) < 8 {
			return e, ErrMalformed
		}
		e.VR = string(p.b[4:6])
		if longVR(e.VR) {
			if len(p.b) < 12 {
				return e, ErrMalformed
			}
			length = binary.LittleEndian.Uint32(p.b[8:12])
			p.b = p.b[12:]
		} else {
			length = uint32(binary.LittleEndian.Uint16(p.b[6:8]))
			p.b = p.b[8:]
		}
	} else {
		if len(p.b) < 8 {
			return e, ErrMalformed
		}
		e.VR = dictVR(t)
		length = binary.LittleEndian.Uint32(p.b[4:8])
		p.b = p.b[8:]
	}

	if length == undefinedLength {
		// a sequence, or a UN/OB value encoded as one
		e.VR = "SQ"
		return e, p.skipSequence(depth + 1)
	}
	if uint64(length) > uint64(len(p.b)) {
		return e, ErrMalformed
	}
	if e.VR != "SQ" {
		e.Value = p.b[:length]
	}
	p.b = p.b[length:]
	return e, nil
}

// skipSequence consumes items up to and including the sequence delimiter.
func (p *dsParser) skipSequence(depth int) error {
	if depth > maxDepth {
		return ErrMalformed
	}
	for {
		t, ok := p.tag()
		if !ok || len(p.b) < 8 {
			return ErrMalformed
		}
		length := binary.LittleEndian.Uint32(p.b[4:8])
		p.b = p.b[8:]
		switch t {
		case tagSeqDelim:
			return nil
		case tagItem:
		default:
			return ErrMalformed
		}
		if length != undefinedLength {
			if uint64(length) > uint64(len(p.b)) {
				return ErrMalformed
			}
			p.b = p.b[length:]
			continue
		}
		for {
			t, ok := p.tag()
			if !ok {
				return ErrMalformed
			}
			if t == tagItemDelim {
				if len(p.b) < 8 {
					return ErrMalformed
				}
				p.b = p.b[8:]
				break
			}
			if _, err := p.next(depth); err != nil {
				return err
			}
		}
	}
}

// ParseDataSet decodes the top-level elements of a data set encoded in the
// given transfer syntax. Elements decoded before an error are returned with it.
func ParseDataSet(b []byte, transferSyntax string) ([]Element, error) {
	explicit, err := explicitVR(transferSyntax)
	if err != nil {
		return nil, err
	}
	p := dsParser{b: b, explicit: explicit}
	var out []Element
	for len(p.b) > 0 {
		if len(out) >= maxElements {
			return out, ErrMalformed
		}
		e, err := p.next(0)
		if err != nil {
			return out, err
		}
		out = append(out, e)
	}
	return out, nil
}

func stringValue(v []byte) string {
	return strings.TrimRight(string(v), "\x00 ")
}

// QueryMap renders elements as keyword → value for the decoded event. String
// values are trimmed, binary or non-UTF-8 values are hex encoded, sequences
// are empty.
func QueryMap(elems []Element) map[string]string {
	if len(elems) == 0 {
		return nil
	}
	out := make(map[string]string, len(elems))
	for _, e := range elems {
		v := e.Value
		if len(v) > maxQueryValue {
			v = v[:maxQueryValue]
		}
		s := stringValue(v)
		if binaryVR(e.VR) || !utf8.ValidString(s) {
			s = hex.EncodeToString(v)
		}
		out[Keyword(e.Tag)] = s
	}
	return out
}

func padValue(vr string, v []byte) []byte {
	if len(v)%2 == 0 {
		return v
	}
	pad := byte(' ')
	if vr == "UI" || binaryVR(vr) {
		pad = 0
	}
	return append(append([]byte{}, v...), pad)
}

// EncodeDataSet encodes elements (in ascending tag order) in the given
// transfer syntax. Elements with an empty VR take it from the dictionary or
// fall back to UN; sequences are encoded empty.
func EncodeDataSet(elems []Element, transferSyntax string) ([]byte, error) {
	explicit, err := explicitVR(transferSyntax)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, e := range elems {
		vr := e.VR
		if vr == "" {
			vr = dictVR(e.Tag)
		}
		if vr == "" {
			vr = "UN"
		}
		v := padValue(vr, e.Value)
		if vr == "SQ" {
			v = nil
		}
		out = binary.LittleEndian.AppendUint16(out, uint16(e.Tag>>16))
		out = binary.LittleEndian.AppendUint16(out, uint16(e.Tag))
		switch {
		case !explicit:
			out = binary.LittleEndian.AppendUint32(out, uint32(len(v)))
		case longVR(vr):
			out = append(out, vr[0], vr[1], 0, 0)
			out = binary.LittleEndian.AppendUint32(out, uint32(len(v)))
		default:
			if len(v) > 0xFFFF {
				return nil, ErrMalformed
			}
			out = append(out, vr[0], vr[1])
			out = binary.LittleEndian.AppendUint16(out, uint16(len(v)))
		}
		out = append(out, v...)
	}
	return out, nil
}
