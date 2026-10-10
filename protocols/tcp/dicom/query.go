package dicom

import (
	"errors"
	"strings"
)

// Query/Retrieve FIND information models (PS3.4 annex C) that get matches.
// Other C-FIND SOP classes (e.g. modality worklist) find nothing.
const (
	PatientRootFind      = "1.2.840.10008.5.1.4.1.2.1.1"
	StudyRootFind        = "1.2.840.10008.5.1.4.1.2.2.1"
	PatientStudyOnlyFind = "1.2.840.10008.5.1.4.1.2.3.1"
)

const (
	tagQueryRetrieveLevel   Tag = 0x00080052
	tagRetrieveAETitle      Tag = 0x00080054
	tagSpecificCharacterSet Tag = 0x00080005
)

// Record is one synthetic archive entry holding the patient, study, series
// and instance attributes of a single image. The archive is fictional: like
// dicompot (github.com/nsmfoo/dicompot, Apache-2.0) the server answers
// C-FIND with matches, but no real patient data or images are shipped.
type Record map[Tag]string

// Archive is the synthetic content searched by C-FIND.
var Archive = []Record{
	newRecord("MILLER^ANNA", "4021187", "19640312", "F", "CT", "CT THORAX MIT KM", "THORAX 1.5 B31F",
		"20240917", "093412", "A24091701", "1.2.276.0.7230010.3.1.2.2831156423.4120.1726558452.215"),
	newRecord("NOVAK^PETER", "4021903", "19581104", "M", "MR", "MRT KNIE LINKS", "PD TSE COR",
		"20241002", "141055", "A24100214", "1.2.276.0.7230010.3.1.2.2831156423.4120.1727871055.731"),
	newRecord("WEBER^THOMAS", "4022415", "19770629", "M", "CR", "ROE THORAX PA", "PA",
		"20241015", "080127", "A24101502", "1.2.276.0.7230010.3.1.2.2831156423.4120.1728972087.104"),
}

func newRecord(name, id, birth, sex, modality, studyDesc, seriesDesc, date, time, accession, studyUID string) Record {
	return Record{
		0x00100010: name,
		0x00100020: id,
		0x00100030: birth,
		0x00100040: sex,
		0x0020000D: studyUID,
		0x00080020: date,
		0x00080030: time,
		0x00080050: accession,
		0x00200010: accession[len(accession)-4:],
		0x00081030: studyDesc,
		0x00080061: modality,
		0x00080090: "",
		0x0020000E: studyUID + ".1",
		0x00200011: "1",
		0x00080060: modality,
		0x0008103E: seriesDesc,
		0x00080021: date,
		0x00080016: imageStorageClass(modality),
		0x00080018: studyUID + ".1.1",
		0x00200013: "1",
		0x00201200: "1",
		0x00201206: "1",
		0x00201208: "1",
		0x00201209: "1",
		0x00080056: "ONLINE",
	}
}

func imageStorageClass(modality string) string {
	switch modality {
	case "CT":
		return "1.2.840.10008.5.1.4.1.1.2"
	case "MR":
		return "1.2.840.10008.5.1.4.1.1.4"
	}
	return "1.2.840.10008.5.1.4.1.1.1"
}

// wildcard matches s against a pattern with * and ? (PS3.4 C.2.2.2.4).
func wildcard(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// matchValue applies single value, wildcard, list of UID and range matching.
func matchValue(vr, query, value string) bool {
	if query == "" || query == "*" {
		return true
	}
	if strings.Contains(query, "\\") {
		for _, q := range strings.Split(query, "\\") {
			if matchValue(vr, q, value) {
				return true
			}
		}
		return false
	}
	if (vr == "DA" || vr == "TM" || vr == "DT") && strings.Contains(query, "-") {
		lo, hi, _ := strings.Cut(query, "-")
		return (lo == "" || value >= lo) && (hi == "" || value[:min(len(hi), len(value))] <= hi)
	}
	return wildcard(strings.ToUpper(query), strings.ToUpper(value))
}

func (r Record) matches(identifier []Element) bool {
	for _, e := range identifier {
		value, ok := r[e.Tag]
		if !ok || e.VR == "SQ" {
			continue
		}
		vr := e.VR
		if vr == "" {
			vr = dictVR(e.Tag)
		}
		if !matchValue(vr, stringValue(e.Value), value) {
			return false
		}
	}
	return true
}

// Find returns one response identifier per archive record matching the
// request identifier. Only the requested attributes are returned; ones the
// archive does not know are returned empty.
func Find(sopClass string, identifier []Element, retrieveAE string) [][]Element {
	switch sopClass {
	case PatientRootFind, StudyRootFind, PatientStudyOnlyFind:
	default:
		return nil
	}
	var out [][]Element
	for _, r := range Archive {
		if !r.matches(identifier) {
			continue
		}
		resp := make([]Element, 0, len(identifier))
		for _, e := range identifier {
			el := Element{Tag: e.Tag, VR: e.VR}
			switch e.Tag {
			case tagQueryRetrieveLevel, tagSpecificCharacterSet:
				el.Value = e.Value
			case tagRetrieveAETitle:
				el.Value = []byte(retrieveAE)
			default:
				if v, ok := r[e.Tag]; ok && e.VR != "SQ" {
					el.Value = []byte(v)
				}
			}
			resp = append(resp, el)
		}
		out = append(out, resp)
	}
	return out
}

// Reply is one DIMSE response: the command and an optional data set.
type Reply struct {
	Command Command
	DataSet []byte
}

// FindReplies answers a C-FIND-RQ: one Pending reply per match carrying the
// identifier, then the final Success. An identifier that does not decode is
// refused with 0xA900.
func FindReplies(req Command, identifier []byte, transferSyntax, retrieveAE string) []Reply {
	final, _ := Response(req)
	elems, err := ParseDataSet(identifier, transferSyntax)
	switch {
	case errors.Is(err, ErrUnsupportedTransferSyntax):
		return []Reply{{Command: final}}
	case err != nil || len(elems) == 0:
		final.Status = StatusIdentifierMismatch
		return []Reply{{Command: final}}
	}
	var replies []Reply
	for _, match := range Find(req.SOPClassUID, elems, retrieveAE) {
		ds, err := EncodeDataSet(match, transferSyntax)
		if err != nil {
			continue
		}
		pending := final
		pending.DataSetType = 0
		pending.Status = StatusPending
		replies = append(replies, Reply{Command: pending, DataSet: ds})
	}
	return append(replies, Reply{Command: final})
}
