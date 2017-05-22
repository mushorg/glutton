package smb

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"time"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
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
}

type Filetime struct {
	low  uint32
	high uint32
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

func MakeNegotiateProtocolResponse(req *NegotiateProtocolRequest) ([]byte, error) {
	smb := NegotiateProtocolResponse{}
	smb.Header.Protocol = req.Header.Protocol
	smb.Header.Command = req.Header.Command
	smb.Header.Status = [4]byte{0, 0, 0, 0}
	smb.Header.Flags = 0x98
	smb.Header.Flags2 = [2]byte{28, 1}
	smb.StructureSize = [2]byte{65}
	smb.SecurityMode = [2]byte{0x0003}
	smb.DialectRevision = [2]byte{0x03, 0x00}
	copy(smb.ServerGUID[:], uuid.NewV4().Bytes())
	smb.Capabilities = [4]byte{0x80, 0x01, 0xe3, 0xfc}
	smb.MaxTransactSize = [4]byte{0x04, 0x11}
	smb.MaxReadSize = [4]byte{0x00, 0x00, 0x01}
	smb.SystemTime = filetime(0)
	smb.ServerStartTime = filetime(time.Duration(random(1000, 2000)) * time.Hour)

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, smb)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ParseSMB(data []byte) (smb NegotiateProtocolRequest, err error) {
	smb = NegotiateProtocolRequest{}
	// HACK: Not sure what the data in front is supposed to be...
	if !bytes.Contains(data, []byte("\xff")) {
		err = errors.New("Packet is unrecognizable")
		return
	}

	start := bytes.Index(data, []byte("\xff"))
	buffer := bytes.NewBuffer(data[start:])
	err = binary.Read(buffer, binary.LittleEndian, &smb.Header)
	if err != nil {
		return
	}
	err = binary.Read(buffer, binary.LittleEndian, &smb.Param)
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
