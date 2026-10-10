// Package dicom parses and builds DICOM Upper Layer (DUL) PDUs and DIMSE
// command sets, as spoken by PACS and modality nodes on tcp/104 and tcp/11112
// (PS3.8 section 9, PS3.7 section 9). A session starts with an
// A-ASSOCIATE-RQ naming the called/calling AE titles and the proposed
// presentation contexts, e.g. from mushorg/glutton#50:
//
//	01 00 00 00 01 00   A-ASSOCIATE-RQ, length 256
//	00 01 00 00         protocol version 1
//	ANY-SCP / FINDSCU   called / calling AE titles (16 bytes each)
//	10 ... 20 ... 50    application context, presentation context, user info
//
// After an A-ASSOCIATE-AC, DIMSE messages (C-ECHO, C-FIND, C-STORE, ...) are
// carried in P-DATA-TF PDUs as command and data set fragments.
package dicom

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// PDU types (PS3.8 table 9-11).
const (
	PDUAssociateRQ byte = 0x01
	PDUAssociateAC byte = 0x02
	PDUAssociateRJ byte = 0x03
	PDUPData       byte = 0x04
	PDUReleaseRQ   byte = 0x05
	PDUReleaseRP   byte = 0x06
	PDUAbort       byte = 0x07
)

// Variable item types inside A-ASSOCIATE-RQ/AC.
const (
	itemApplicationContext   byte = 0x10
	itemPresentationContext  byte = 0x20
	itemPresentationContextA byte = 0x21
	itemAbstractSyntax       byte = 0x30
	itemTransferSyntax       byte = 0x40
	itemUserInfo             byte = 0x50
	itemMaxLength            byte = 0x51
	itemImplClassUID         byte = 0x52
	itemImplVersion          byte = 0x55
	itemUserIdentity         byte = 0x58
	itemUserIdentityAC       byte = 0x59
)

// DIMSE command fields (PS3.7 annex E).
const (
	CStoreRQ       uint16 = 0x0001
	CGetRQ         uint16 = 0x0010
	CFindRQ        uint16 = 0x0020
	CMoveRQ        uint16 = 0x0021
	CEchoRQ        uint16 = 0x0030
	NEventReportRQ uint16 = 0x0100
	NGetRQ         uint16 = 0x0110
	NSetRQ         uint16 = 0x0120
	NActionRQ      uint16 = 0x0130
	NCreateRQ      uint16 = 0x0140
	NDeleteRQ      uint16 = 0x0150
	CCancelRQ      uint16 = 0x0FFF
	responseBit    uint16 = 0x8000
	noDataSet      uint16 = 0x0101
	StatusSuccess  uint16 = 0x0000
	StatusUnrecOp  uint16 = 0x0211
	StatusPending  uint16 = 0xFF00
	// StatusMoveDestinationUnknown refuses C-MOVE to an AE that is not configured.
	StatusMoveDestinationUnknown uint16 = 0xA801
	// StatusOutOfResourcesSubOps refuses C-GET: unable to perform sub-operations.
	StatusOutOfResourcesSubOps uint16 = 0xA702
	// StatusIdentifierMismatch: data set does not match SOP class.
	StatusIdentifierMismatch uint16 = 0xA900
)

// Command set element tags (group 0000).
const (
	tagGroupLength            uint16 = 0x0000
	tagAffectedSOPClassUID    uint16 = 0x0002
	tagRequestedSOPClassUID   uint16 = 0x0003
	tagCommandField           uint16 = 0x0100
	tagMessageID              uint16 = 0x0110
	tagMessageIDRespondedTo   uint16 = 0x0120
	tagMoveDestination        uint16 = 0x0600
	tagPriority               uint16 = 0x0700
	tagCommandDataSetType     uint16 = 0x0800
	tagStatus                 uint16 = 0x0900
	tagAffectedSOPInstanceUID uint16 = 0x1000
	tagRequestedSOPInstance   uint16 = 0x1001
	tagRemainingSubOps        uint16 = 0x1020
	tagCompletedSubOps        uint16 = 0x1021
	tagFailedSubOps           uint16 = 0x1022
	tagWarningSubOps          uint16 = 0x1023
)

const (
	// HeaderLen is the fixed PDU header: type, reserved, 4-byte length.
	HeaderLen = 6
	// MaxPDULength bounds the claimed PDU body length we are willing to read.
	MaxPDULength = 1 << 20
	// MaxReceiveLength is the maximum P-DATA-TF length advertised in A-ASSOCIATE-AC.
	MaxReceiveLength = 16384
	// MaxDataSet bounds how many data set bytes are kept per DIMSE message.
	MaxDataSet = 8 << 20

	aeTitleLen = 16

	ApplicationContextUID  = "1.2.840.10008.3.1.1.1"
	ImplicitVRLittleEndian = "1.2.840.10008.1.2"
	ExplicitVRLittleEndian = "1.2.840.10008.1.2.1"
	VerificationSOPClass   = "1.2.840.10008.1.1"

	// Identify as a stock DCMTK storescp, the most common open source SCP.
	ImplementationClassUID = "1.2.276.0.7230010.3.0.3.6.4"
	ImplementationVersion  = "OFFIS_DCMTK_364"
)

var (
	ErrMalformed   = errors.New("malformed DICOM PDU")
	ErrPDUTooLarge = errors.New("DICOM PDU too large")
)

// ReadPDU reads one PDU and returns it including the 6-byte header. Claimed
// lengths above MaxPDULength are rejected without reading the body.
func ReadPDU(r io.Reader) ([]byte, error) {
	hdr := make([]byte, HeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[2:6])
	if length > MaxPDULength {
		return nil, fmt.Errorf("%w: %d", ErrPDUTooLarge, length)
	}
	buf := make([]byte, HeaderLen+int(length))
	copy(buf, hdr)
	if _, err := io.ReadFull(r, buf[HeaderLen:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// PDUTypeName returns the PS3.8 name of a PDU type.
func PDUTypeName(t byte) string {
	switch t {
	case PDUAssociateRQ:
		return "A-ASSOCIATE-RQ"
	case PDUAssociateAC:
		return "A-ASSOCIATE-AC"
	case PDUAssociateRJ:
		return "A-ASSOCIATE-RJ"
	case PDUPData:
		return "P-DATA-TF"
	case PDUReleaseRQ:
		return "A-RELEASE-RQ"
	case PDUReleaseRP:
		return "A-RELEASE-RP"
	case PDUAbort:
		return "A-ABORT"
	}
	return fmt.Sprintf("UNKNOWN-0x%02x", t)
}

// PresentationContext is one proposed presentation context.
type PresentationContext struct {
	ID               byte
	AbstractSyntax   string
	TransferSyntaxes []string
}

// AssociateRQ is a parsed A-ASSOCIATE-RQ.
type AssociateRQ struct {
	ProtocolVersion        uint16
	CalledAE               string
	CallingAE              string
	ApplicationContext     string
	PresentationContexts   []PresentationContext
	MaxLength              uint32
	ImplementationClassUID string
	ImplementationVersion  string
	UserIdentityType       byte
	UserIdentityResponse   bool
	Username               string

	rawCalledAE  []byte
	rawCallingAE []byte
}

// AbstractSyntaxes lists the proposed abstract syntax UIDs in order.
func (rq AssociateRQ) AbstractSyntaxes() []string {
	var out []string
	for _, pc := range rq.PresentationContexts {
		if pc.AbstractSyntax != "" {
			out = append(out, pc.AbstractSyntax)
		}
	}
	return out
}

// TransferSyntaxes lists the distinct proposed transfer syntax UIDs in order.
func (rq AssociateRQ) TransferSyntaxes() []string {
	var out []string
	seen := map[string]bool{}
	for _, pc := range rq.PresentationContexts {
		for _, ts := range pc.TransferSyntaxes {
			if !seen[ts] {
				seen[ts] = true
				out = append(out, ts)
			}
		}
	}
	return out
}

type item struct {
	typ   byte
	value []byte
}

// splitItems splits a run of type/reserved/2-byte-length items.
func splitItems(b []byte) ([]item, error) {
	var items []item
	for len(b) > 0 {
		if len(b) < 4 {
			return items, ErrMalformed
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if len(b) < 4+n {
			return items, ErrMalformed
		}
		items = append(items, item{typ: b[0], value: b[4 : 4+n]})
		b = b[4+n:]
	}
	return items, nil
}

func uid(b []byte) string {
	return strings.TrimRight(string(b), "\x00 ")
}

func aeTitle(b []byte) string {
	return strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
}

// ParseAssociateRQ parses a full A-ASSOCIATE-RQ PDU (header included). Fields
// decoded before a malformed item are returned alongside ErrMalformed.
func ParseAssociateRQ(pdu []byte) (AssociateRQ, error) {
	var rq AssociateRQ
	const fixed = HeaderLen + 4 + 2*aeTitleLen + 32
	if len(pdu) < fixed || pdu[0] != PDUAssociateRQ {
		return rq, ErrMalformed
	}
	b := pdu[HeaderLen:]
	rq.ProtocolVersion = binary.BigEndian.Uint16(b[0:2])
	rq.rawCalledAE = b[4 : 4+aeTitleLen]
	rq.rawCallingAE = b[4+aeTitleLen : 4+2*aeTitleLen]
	rq.CalledAE = aeTitle(rq.rawCalledAE)
	rq.CallingAE = aeTitle(rq.rawCallingAE)

	items, err := splitItems(b[4+2*aeTitleLen+32:])
	for _, it := range items {
		switch it.typ {
		case itemApplicationContext:
			rq.ApplicationContext = uid(it.value)
		case itemPresentationContext:
			pc, perr := parsePresentationContext(it.value)
			if perr != nil {
				err = perr
			}
			rq.PresentationContexts = append(rq.PresentationContexts, pc)
		case itemUserInfo:
			if uerr := rq.parseUserInfo(it.value); uerr != nil {
				err = uerr
			}
		}
	}
	return rq, err
}

func parsePresentationContext(b []byte) (PresentationContext, error) {
	var pc PresentationContext
	if len(b) < 4 {
		return pc, ErrMalformed
	}
	pc.ID = b[0]
	subs, err := splitItems(b[4:])
	for _, s := range subs {
		switch s.typ {
		case itemAbstractSyntax:
			pc.AbstractSyntax = uid(s.value)
		case itemTransferSyntax:
			pc.TransferSyntaxes = append(pc.TransferSyntaxes, uid(s.value))
		}
	}
	return pc, err
}

func (rq *AssociateRQ) parseUserInfo(b []byte) error {
	subs, err := splitItems(b)
	for _, s := range subs {
		switch s.typ {
		case itemMaxLength:
			if len(s.value) >= 4 {
				rq.MaxLength = binary.BigEndian.Uint32(s.value)
			}
		case itemImplClassUID:
			rq.ImplementationClassUID = uid(s.value)
		case itemImplVersion:
			rq.ImplementationVersion = strings.TrimSpace(string(s.value))
		case itemUserIdentity:
			// type, positive-response-requested, 2-byte primary length, primary,
			// 2-byte secondary length, secondary (passcode, not recorded).
			if len(s.value) < 4 {
				err = ErrMalformed
				continue
			}
			rq.UserIdentityType = s.value[0]
			rq.UserIdentityResponse = s.value[1] == 1
			n := int(binary.BigEndian.Uint16(s.value[2:4]))
			if len(s.value) < 4+n {
				err = ErrMalformed
				continue
			}
			// 1 = username, 2 = username and passcode
			if rq.UserIdentityType == 1 || rq.UserIdentityType == 2 {
				rq.Username = string(s.value[4 : 4+n])
			}
		}
	}
	return err
}

func appendItem(dst []byte, typ byte, value []byte) []byte {
	dst = append(dst, typ, 0)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(value)))
	return append(dst, value...)
}

func appendPDU(typ byte, body []byte) []byte {
	out := make([]byte, 0, HeaderLen+len(body))
	out = append(out, typ, 0)
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	return append(out, body...)
}

func padAE(raw []byte, title string) []byte {
	if len(raw) == aeTitleLen {
		return raw
	}
	b := []byte(fmt.Sprintf("%-16s", title))
	return b[:aeTitleLen]
}

// chooseTransferSyntax prefers Implicit VR Little Endian (always supported by
// real SCPs), then Explicit VR Little Endian, then whatever came first.
func chooseTransferSyntax(offered []string) (string, bool) {
	for _, want := range []string{ImplicitVRLittleEndian, ExplicitVRLittleEndian} {
		for _, ts := range offered {
			if ts == want {
				return ts, true
			}
		}
	}
	if len(offered) > 0 {
		return offered[0], true
	}
	return ImplicitVRLittleEndian, false
}

// AcceptedContexts maps each presentation context accepted by
// BuildAssociateAC to its chosen transfer syntax.
func AcceptedContexts(rq AssociateRQ) map[byte]string {
	out := make(map[byte]string, len(rq.PresentationContexts))
	for _, pc := range rq.PresentationContexts {
		if ts, ok := chooseTransferSyntax(pc.TransferSyntaxes); ok {
			out[pc.ID] = ts
		}
	}
	return out
}

// BuildAssociateAC accepts every proposed presentation context.
func BuildAssociateAC(rq AssociateRQ) []byte {
	body := make([]byte, 0, 256)
	body = append(body, 0x00, 0x01, 0x00, 0x00) // protocol version 1, reserved
	body = append(body, padAE(rq.rawCalledAE, rq.CalledAE)...)
	body = append(body, padAE(rq.rawCallingAE, rq.CallingAE)...)
	body = append(body, make([]byte, 32)...)

	appCtx := rq.ApplicationContext
	if appCtx == "" {
		appCtx = ApplicationContextUID
	}
	body = appendItem(body, itemApplicationContext, []byte(appCtx))

	for _, pc := range rq.PresentationContexts {
		ts, ok := chooseTransferSyntax(pc.TransferSyntaxes)
		result := byte(0) // acceptance
		if !ok {
			result = 4 // transfer syntaxes not supported
		}
		v := []byte{pc.ID, 0, result, 0}
		v = appendItem(v, itemTransferSyntax, []byte(ts))
		body = appendItem(body, itemPresentationContextA, v)
	}

	var ui []byte
	ui = appendItem(ui, itemMaxLength, binary.BigEndian.AppendUint32(nil, MaxReceiveLength))
	ui = appendItem(ui, itemImplClassUID, []byte(ImplementationClassUID))
	ui = appendItem(ui, itemImplVersion, []byte(ImplementationVersion))
	if rq.UserIdentityResponse {
		// empty server response: username/passcode identities carry none
		ui = appendItem(ui, itemUserIdentityAC, []byte{0, 0})
	}
	body = appendItem(body, itemUserInfo, ui)
	return appendPDU(PDUAssociateAC, body)
}

// BuildAssociateRJ builds an A-ASSOCIATE-RJ with the given result, source and reason.
func BuildAssociateRJ(result, source, reason byte) []byte {
	return appendPDU(PDUAssociateRJ, []byte{0, result, source, reason})
}

// BuildReleaseRP builds an A-RELEASE-RP.
func BuildReleaseRP() []byte {
	return appendPDU(PDUReleaseRP, []byte{0, 0, 0, 0})
}

// BuildAbort builds an A-ABORT with the given source and reason.
func BuildAbort(source, reason byte) []byte {
	return appendPDU(PDUAbort, []byte{0, 0, source, reason})
}

// PDV is one presentation data value from a P-DATA-TF PDU.
type PDV struct {
	ContextID byte
	Command   bool
	Last      bool
	Data      []byte
}

// ParsePData splits a full P-DATA-TF PDU (header included) into its PDVs.
func ParsePData(pdu []byte) ([]PDV, error) {
	if len(pdu) < HeaderLen || pdu[0] != PDUPData {
		return nil, ErrMalformed
	}
	var pdvs []PDV
	b := pdu[HeaderLen:]
	for len(b) > 0 {
		if len(b) < 6 {
			return pdvs, ErrMalformed
		}
		n := int(binary.BigEndian.Uint32(b[0:4]))
		if n < 2 || len(b) < 4+n {
			return pdvs, ErrMalformed
		}
		mch := b[5]
		pdvs = append(pdvs, PDV{
			ContextID: b[4],
			Command:   mch&0x01 != 0,
			Last:      mch&0x02 != 0,
			Data:      b[6 : 4+n],
		})
		b = b[4+n:]
	}
	return pdvs, nil
}

// BuildPData wraps one complete command or data set fragment in a P-DATA-TF.
func BuildPData(contextID byte, command, last bool, data []byte) []byte {
	return BuildPDataPDVs(PDV{ContextID: contextID, Command: command, Last: last, Data: data})
}

// BuildPDataPDVs wraps several PDVs in one P-DATA-TF.
func BuildPDataPDVs(pdvs ...PDV) []byte {
	var body []byte
	for _, pdv := range pdvs {
		var mch byte
		if pdv.Command {
			mch |= 0x01
		}
		if pdv.Last {
			mch |= 0x02
		}
		body = binary.BigEndian.AppendUint32(body, uint32(len(pdv.Data)+2))
		body = append(body, pdv.ContextID, mch)
		body = append(body, pdv.Data...)
	}
	return appendPDU(PDUPData, body)
}

// Command is a decoded DIMSE command set.
type Command struct {
	Field           uint16
	MessageID       uint16
	RespondedTo     uint16
	SOPClassUID     string // affected or requested SOP class
	SOPInstanceUID  string // affected or requested SOP instance
	MoveDestination string
	Priority        uint16
	DataSetType     uint16
	Status          uint16
}

// HasDataSet reports whether a data set follows the command.
func (c Command) HasDataSet() bool {
	return c.DataSetType != noDataSet
}

// IsResponse reports whether the command field is a response.
func (c Command) IsResponse() bool {
	return c.Field&responseBit != 0
}

// CommandName returns the PS3.7 name of a DIMSE command field.
func CommandName(field uint16) string {
	names := map[uint16]string{
		CStoreRQ: "C-STORE", CGetRQ: "C-GET", CFindRQ: "C-FIND", CMoveRQ: "C-MOVE",
		CEchoRQ: "C-ECHO", NEventReportRQ: "N-EVENT-REPORT", NGetRQ: "N-GET",
		NSetRQ: "N-SET", NActionRQ: "N-ACTION", NCreateRQ: "N-CREATE", NDeleteRQ: "N-DELETE",
	}
	if field == CCancelRQ {
		return "C-CANCEL-RQ"
	}
	if name, ok := names[field&^responseBit]; ok {
		if field&responseBit != 0 {
			return name + "-RSP"
		}
		return name + "-RQ"
	}
	return fmt.Sprintf("UNKNOWN-0x%04x", field)
}

// StatusName returns a short name for a DIMSE status.
func StatusName(status uint16) string {
	switch status {
	case StatusSuccess:
		return "Success"
	case StatusUnrecOp:
		return "UnrecognizedOperation"
	case StatusPending:
		return "Pending"
	case StatusMoveDestinationUnknown:
		return "MoveDestinationUnknown"
	case StatusOutOfResourcesSubOps:
		return "OutOfResources"
	case StatusIdentifierMismatch:
		return "IdentifierDoesNotMatchSOPClass"
	}
	return fmt.Sprintf("0x%04x", status)
}

// ParseCommand decodes a command set (always Implicit VR Little Endian).
func ParseCommand(b []byte) (Command, error) {
	var c Command
	sawField := false
	for len(b) > 0 {
		if len(b) < 8 {
			return c, ErrMalformed
		}
		group := binary.LittleEndian.Uint16(b[0:2])
		elem := binary.LittleEndian.Uint16(b[2:4])
		n := binary.LittleEndian.Uint32(b[4:8])
		if group != 0 || uint64(n) > uint64(len(b)-8) {
			return c, ErrMalformed
		}
		v := b[8 : 8+n]
		b = b[8+n:]
		us := uint16(0)
		if len(v) >= 2 {
			us = binary.LittleEndian.Uint16(v)
		}
		switch elem {
		case tagCommandField:
			c.Field, sawField = us, true
		case tagMessageID:
			c.MessageID = us
		case tagMessageIDRespondedTo:
			c.RespondedTo = us
		case tagAffectedSOPClassUID, tagRequestedSOPClassUID:
			c.SOPClassUID = uid(v)
		case tagAffectedSOPInstanceUID, tagRequestedSOPInstance:
			c.SOPInstanceUID = uid(v)
		case tagMoveDestination:
			c.MoveDestination = aeTitle(v)
		case tagPriority:
			c.Priority = us
		case tagCommandDataSetType:
			c.DataSetType = us
		case tagStatus:
			c.Status = us
		}
	}
	if !sawField {
		return c, ErrMalformed
	}
	return c, nil
}

type element struct {
	tag   uint16
	value []byte
}

func usValue(v uint16) []byte {
	return binary.LittleEndian.AppendUint16(nil, v)
}

func uiValue(s string) []byte {
	b := []byte(s)
	if len(b)%2 == 1 {
		b = append(b, 0)
	}
	return b
}

// encodeCommand writes elements (in ascending tag order) preceded by the
// mandatory (0000,0000) group length.
func encodeCommand(elems []element) []byte {
	var body []byte
	for _, e := range elems {
		body = binary.LittleEndian.AppendUint16(body, 0)
		body = binary.LittleEndian.AppendUint16(body, e.tag)
		body = binary.LittleEndian.AppendUint32(body, uint32(len(e.value)))
		body = append(body, e.value...)
	}
	out := make([]byte, 0, 12+len(body))
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, tagGroupLength)
	out = binary.LittleEndian.AppendUint32(out, 4)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(body)))
	return append(out, body...)
}

// Response returns the (final) response command for a request, or false when
// no response is due (responses, C-CANCEL). C-ECHO, C-STORE and C-FIND
// succeed; C-MOVE is refused because no destination AE is configured and
// C-GET because no sub-operations can be performed, so the server never
// connects out or sends images. N-* services are not supported.
func Response(req Command) (Command, bool) {
	if req.IsResponse() || req.Field == CCancelRQ {
		return Command{}, false
	}
	resp := Command{
		Field:          req.Field | responseBit,
		RespondedTo:    req.MessageID,
		SOPClassUID:    req.SOPClassUID,
		SOPInstanceUID: req.SOPInstanceUID,
		DataSetType:    noDataSet,
		Status:         StatusSuccess,
	}
	switch req.Field {
	case CEchoRQ:
		if resp.SOPClassUID == "" {
			resp.SOPClassUID = VerificationSOPClass
		}
	case CStoreRQ, CFindRQ:
	case CMoveRQ:
		resp.Status = StatusMoveDestinationUnknown
	case CGetRQ:
		resp.Status = StatusOutOfResourcesSubOps
	default:
		resp.Status = StatusUnrecOp
	}
	return resp, true
}

// EncodeCommand encodes a response command set.
func EncodeCommand(c Command) []byte {
	var elems []element
	if c.SOPClassUID != "" {
		elems = append(elems, element{tagAffectedSOPClassUID, uiValue(c.SOPClassUID)})
	}
	elems = append(elems,
		element{tagCommandField, usValue(c.Field)},
		element{tagMessageIDRespondedTo, usValue(c.RespondedTo)},
		element{tagCommandDataSetType, usValue(c.DataSetType)},
		element{tagStatus, usValue(c.Status)},
	)
	if c.SOPInstanceUID != "" && c.Field == CStoreRQ|responseBit {
		elems = append(elems, element{tagAffectedSOPInstanceUID, uiValue(c.SOPInstanceUID)})
	}
	if c.Field == CGetRQ|responseBit || c.Field == CMoveRQ|responseBit {
		elems = append(elems,
			element{tagRemainingSubOps, usValue(0)},
			element{tagCompletedSubOps, usValue(0)},
			element{tagFailedSubOps, usValue(0)},
			element{tagWarningSubOps, usValue(0)},
		)
	}
	return encodeCommand(elems)
}

// Message is a fully reassembled DIMSE message.
type Message struct {
	ContextID byte
	Command   Command
	DataSet   []byte
	Truncated bool // data set exceeded MaxDataSet
}

// Assembler reassembles command and data set fragments from PDVs into DIMSE
// messages.
type Assembler struct {
	contextID byte
	command   []byte
	cmd       *Command
	dataSet   []byte
	truncated bool
}

func (a *Assembler) reset() {
	*a = Assembler{}
}

// Add feeds one PDV and returns a message once its last fragment arrived.
func (a *Assembler) Add(pdv PDV) (*Message, error) {
	if pdv.Command {
		if a.cmd != nil {
			// a new command before the previous data set finished
			a.reset()
			return nil, ErrMalformed
		}
		a.contextID = pdv.ContextID
		if len(a.command)+len(pdv.Data) > MaxPDULength {
			a.reset()
			return nil, ErrMalformed
		}
		a.command = append(a.command, pdv.Data...)
		if !pdv.Last {
			return nil, nil
		}
		cmd, err := ParseCommand(a.command)
		if err != nil {
			a.reset()
			return nil, err
		}
		if !cmd.HasDataSet() {
			a.reset()
			return &Message{ContextID: pdv.ContextID, Command: cmd}, nil
		}
		a.cmd = &cmd
		a.command = nil
		return nil, nil
	}

	if a.cmd == nil {
		return nil, ErrMalformed
	}
	room := MaxDataSet - len(a.dataSet)
	if len(pdv.Data) > room {
		a.dataSet = append(a.dataSet, pdv.Data[:room]...)
		a.truncated = true
	} else {
		a.dataSet = append(a.dataSet, pdv.Data...)
	}
	if !pdv.Last {
		return nil, nil
	}
	msg := &Message{ContextID: a.contextID, Command: *a.cmd, DataSet: a.dataSet, Truncated: a.truncated}
	a.reset()
	return msg, nil
}
