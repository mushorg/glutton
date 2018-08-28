package smb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"time"

	"github.com/satori/go.uuid"
)

type SMBHeader struct {
	Protocol         [4]byte
	Command          byte
	Status           [4]byte
	Flags            byte
	Flags2           [2]byte
	PIDHigh          [2]byte
	SecurityFeatures [8]byte
	Reserved         [2]byte
	TID              [2]byte
	PIDLow           [2]byte
	UID              [2]byte
	MID              [2]byte
}

type SMBParameters struct {
	WordCount byte
}

type SMBData struct {
	ByteCount     [2]byte
	DialectString []byte
}

type NegotiateProtocolRequest struct {
	Header SMBHeader
	Param  SMBParameters
	Data   SMBData
}

type NegotiateProtocolResponse struct {
	Header                 SMBHeader
	StructureSize          [2]byte
	SecurityMode           [2]byte
	DialectRevision        [2]byte
	NegotiateContextCount  [2]byte
	ServerGUID             [16]byte
	Capabilities           [4]byte
	MaxTransactSize        [4]byte
	MaxReadSize            [4]byte
	MaxWriteSize           [4]byte
	SystemTime             Filetime
	ServerStartTime        Filetime
	SecurityBufferOffset   [2]byte
	SecurityBufferLength   [2]byte
	NegotiateContextOffset [4]byte
	//Buffer                 []byte
	//Padding                []byte
	//NegotiateContextList   []byte
}

type Filetime struct {
	low  uint32
	high uint32
}

func ValidateData(data []byte) (*bytes.Buffer, error) {
	// HACK: Not sure what the data in front is supposed to be...
	if !bytes.Contains(data, []byte("\xff")) {
		err := errors.New("Packet is unrecognizable")
		return nil, err
	}

	start := bytes.Index(data, []byte("\xff"))
	buffer := bytes.NewBuffer(data[start:])
	return buffer, nil
}

func filetime(offset time.Duration) Filetime {
	epochAsFiletime := int64(116444736000000000) // January 1, 1970 as MS file time
	hundredsOfNanoseconds := int64(10000000)
	fileTime := epochAsFiletime + time.Now().Add(offset).Unix()*hundredsOfNanoseconds
	return Filetime{
		low:  uint32(fileTime),
		high: uint32(fileTime << 32),
	}
}

func random(min, max int) int {
	rand.Seed(time.Now().Unix())
	return rand.Intn(max-min) + min
}

func toBytes(smb interface{}) ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, smb)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func MakeHeaderResponse(header SMBHeader) ([]byte, error) {
	smb := NegotiateProtocolResponse{}
	smb.Header.Protocol = header.Protocol
	smb.Header.Command = header.Command
	smb.Header.Status = [4]byte{0, 0, 0, 0}
	smb.Header.Flags = 0x98
	smb.Header.Flags2 = [2]byte{28, 1}

	return toBytes(smb)
}

type ComTransaction2Response struct {
	Header                SMBHeader
	WordCount             byte
	TotalParameterCount   [2]byte
	TotalDataCount        [2]byte
	Reserved1             [2]byte
	ParameterCount        [2]byte
	ParameterOffset       [2]byte
	ParameterDisplacement [2]byte
	DataCount             [2]byte
	DataOffset            [2]byte
	DataDisplacement      [2]byte
	SetupCount            byte
	Reserved2             byte
	ByteCount             [2]byte
	Pad1                  byte
	SearchID              [2]byte
	SearchCount           [2]byte
	EndofSearch           [2]byte
	ErrorOffset           [2]byte
	LastNameOffset        [2]byte
	Pad2                  [2]byte
	Data                  [16]byte
	Data1                 [16]byte
	Data2                 [16]byte
	Data3                 [16]byte
	Data4                 [16]byte
	Data5                 [16]byte
	Data6                 [16]byte
	Data7                 [16]byte
	Data8                 [16]byte
	Data9                 [16]byte
	Data10                [16]byte
	Data11                [16]byte
	Data12                [4]byte
}

func MakeComTransaction2Response(header SMBHeader) ([]byte, error) {
	smb := ComTransaction2Response{}
	smb.Header = header
	smb.WordCount = 0x0A
	smb.TotalParameterCount = [2]byte{0x0A}
	smb.TotalDataCount = [2]byte{196}
	smb.Reserved1 = [2]byte{0}
	smb.ParameterCount = [2]byte{10}
	smb.ParameterOffset = [2]byte{56}
	smb.ParameterDisplacement = [2]byte{}
	smb.DataCount = [2]byte{196}
	smb.DataOffset = [2]byte{68}
	smb.DataDisplacement = [2]byte{0}
	smb.SetupCount = 0
	smb.Reserved2 = 2
	smb.ByteCount = [2]byte{209}
	smb.Pad1 = 0
	smb.SearchID = [2]byte{0xff, 0xfd}
	smb.SearchCount = [2]byte{2}
	smb.SearchID = [2]byte{1}
	smb.ErrorOffset = [2]byte{}
	smb.LastNameOffset = [2]byte{96}
	smb.Pad2 = [2]byte{}
	smb.Data = [16]byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x39, 0xa3, 0xda, 0x08, 0x01, 0xd6, 0xd2, 0x01}
	smb.Data1 = [16]byte{0xba, 0xb0, 0x6e, 0x0a, 0x01, 0xd6, 0xd2, 0x01, 0x39, 0xa3, 0xda, 0x08, 0x01, 0xd6, 0xd2, 0x01}
	smb.Data2 = [16]byte{0x39, 0xa3, 0xda, 0x08, 0x01, 0xd6, 0xd2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	smb.Data3 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	smb.Data4 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	smb.Data5 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x00}
	smb.Data6 = [16]byte{0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc2, 0xaf, 0xca, 0x06, 0xcc, 0xd5, 0xd2, 0x01}
	smb.Data7 = [16]byte{0x9d, 0x76, 0x46, 0x90, 0xcc, 0xd5, 0xd2, 0x01, 0xc2, 0xaf, 0xca, 0x06, 0xcc, 0xd5, 0xd2, 0x01}
	smb.Data8 = [16]byte{0xc2, 0xaf, 0xca, 0x06, 0xcc, 0xd5, 0xd2, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	smb.Data9 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}
	smb.Data10 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	smb.Data11 = [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x2e}
	smb.Data12 = [4]byte{0x00, 0x00, 0x00, 0x00}

	return toBytes(smb)
}

type ComTransaction2Error struct {
	Header    SMBHeader
	WordCount byte
	ByteCount [2]byte
}

type ComTransactionResponse struct {
	Header                SMBHeader
	WordCount             byte
	TotalParameterCount   [2]byte
	TotalDataCount        [2]byte
	Reserved1             [2]byte
	ParameterCount        [2]byte
	ParameterOffset       [2]byte
	ParameterDisplacement [2]byte
	DataCount             [2]byte
	DataOffset            [2]byte
	DataDisplacement      [2]byte
	SetupCount            byte
	Reserved2             byte
}

func MakeComTransactionResponse(header SMBHeader) ([]byte, error) {
	smb := ComTransactionResponse{}
	smb.Header = header
	smb.WordCount = 10
	smb.ParameterOffset = [2]byte{56}
	smb.DataOffset = [2]byte{56}

	return toBytes(smb)
}

func MakeComTransaction2Error(header SMBHeader) ([]byte, error) {
	smb := ComTransaction2Error{}
	smb.Header = header
	smb.Header.Status = [4]byte{0x02, 0x00, 0x00, 0xc0}
	smb.WordCount = 0x00
	smb.ByteCount = [2]byte{}

	return toBytes(smb)
}

func MakeNegotiateProtocolResponse(header SMBHeader) ([]byte, error) {
	id := uuid.NewV4()
	smb := NegotiateProtocolResponse{}
	smb.Header.Protocol = header.Protocol
	smb.Header.Command = header.Command
	smb.Header.Status = [4]byte{0, 0, 0, 0}
	smb.Header.Flags = 0x98
	smb.Header.Flags2 = [2]byte{28, 1}
	smb.StructureSize = [2]byte{65}
	smb.SecurityMode = [2]byte{0x0003}
	smb.DialectRevision = [2]byte{0x03, 0x00}
	copy(smb.ServerGUID[:], id.Bytes())
	smb.Capabilities = [4]byte{0x80, 0x01, 0xe3, 0xfc}
	smb.MaxTransactSize = [4]byte{0x04, 0x11}
	smb.MaxReadSize = [4]byte{0x00, 0x00, 0x01}
	smb.SystemTime = filetime(0)
	smb.ServerStartTime = filetime(time.Duration(random(1000, 2000)) * time.Hour)

	return toBytes(smb)
}

func ParseHeader(buffer *bytes.Buffer, header *SMBHeader) error {
	err := binary.Read(buffer, binary.LittleEndian, header)
	if err != nil {
		return err
	}
	return nil
}

func ParseParam(buffer *bytes.Buffer, param *SMBParameters) error {
	err := binary.Read(buffer, binary.LittleEndian, param)
	if err != nil {
		return err
	}
	return nil
}

func ParseNegotiateProtocolRequest(buffer *bytes.Buffer, header SMBHeader) (smb NegotiateProtocolRequest, err error) {
	smb = NegotiateProtocolRequest{}
	smb.Header = header
	err = ParseParam(buffer, &smb.Param)
	if err != nil {
		return
	}
	err = binary.Read(buffer, binary.LittleEndian, &smb.Data.ByteCount)
	if err != nil {
		return
	}
	smb.Data.DialectString = make([]byte, buffer.Len())
	err = binary.Read(buffer, binary.LittleEndian, &smb.Data.DialectString)
	if err != nil {
		return
	}
	return
}
