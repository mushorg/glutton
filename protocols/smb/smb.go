package smb

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
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

type SMB struct {
	Header SMBHeader
	Param  SMBParameters
	Data   SMBData
}

func NegotiateProtocolResponse() SMB {
	smb := SMB{}
	smb.Header.Protocol = [4]byte{255, 83, 77, 66}
	smb.Header.Command = 0x72
	smb.Header.Status = [4]byte{0, 0, 0, 0}
	smb.Header.Flags = 0x98
	smb.Header.Flags2 = [2]byte{28, 1}
	return smb
}

func ParseSMB(data []byte) (smb SMB, err error) {
	smb = SMB{}
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
