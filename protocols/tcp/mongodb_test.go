package tcp

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// tests the Mongo response creation function
func TestCreateOkResponse(t *testing.T) {
	requestHeader := MsgHeader{
		MessageLength: 100,
		RequestID:     12345,
		ResponseTo:    0,
		OpCode:        OpMsg,
	}

	responseHeader, response, err := createOkResponse(requestHeader)
	require.NoError(t, err)
	require.NotNil(t, response)

	require.Equal(t, int32(len(response)), responseHeader.MessageLength)
	require.Equal(t, requestHeader.RequestID+1, responseHeader.RequestID)
	require.Equal(t, requestHeader.RequestID, responseHeader.ResponseTo)
	require.Equal(t, int32(OpMsg), responseHeader.OpCode)

	require.Equal(t, int32(len(response)), int32(binary.LittleEndian.Uint32(response[0:4])))

	// check flags - should be 0
	flags := binary.LittleEndian.Uint32(response[16:20])
	require.Equal(t, uint32(0), flags)

	// check section type - should be 0 (body)
	require.Equal(t, byte(0), response[20])
}

// tests the Mongo handler with a mocked connection
func TestHandleMongoDB(t *testing.T) {
	var requestID int32 = 12345
	var buffer bytes.Buffer

	header := MsgHeader{
		MessageLength: 39, // length of the entire message including header
		RequestID:     requestID,
		ResponseTo:    0,
		OpCode:        OpMsg,
	}
	binary.Write(&buffer, binary.LittleEndian, header)

	// Add flags
	binary.Write(&buffer, binary.LittleEndian, uint32(0))

	// Body
	buffer.WriteByte(0)

	// document - {"hello": "mongodb"}
	docBytes := []byte{
		0x16, 0x00, 0x00, 0x00, // doc size: 22 bytes
		0x02, // string type
		'h', 'e', 'l', 'l', 'o', 0x00,
		0x08, 0x00, 0x00, 0x00, // string length including null terminator
		'm', 'o', 'n', 'g', 'o', 'd', 'b', 0x00,
		0x00, // terminator
	}
	buffer.Write(docBytes)

	message := buffer.Bytes()
	var msgHeader MsgHeader
	err := binary.Read(bytes.NewReader(message[:16]), binary.LittleEndian, &msgHeader)
	require.NoError(t, err)

	responseHeader, response, err := createOkResponse(msgHeader)
	require.NoError(t, err)
	require.NotNil(t, response)

	require.Equal(t, int32(len(response)), responseHeader.MessageLength)
	require.Equal(t, requestID+1, responseHeader.RequestID)
	require.Equal(t, requestID, responseHeader.ResponseTo)
	require.Equal(t, int32(OpMsg), responseHeader.OpCode)

	var respHeader MsgHeader
	err = binary.Read(bytes.NewReader(response[:16]), binary.LittleEndian, &respHeader)
	require.NoError(t, err)

	require.Equal(t, byte(0), response[20])

	// document starts at position 21
	document := response[21:]
	require.True(t, len(document) >= 17, "Document too short")

	// first 4 bytes are document size
	// then type code 0x01 (double) followed by "ok"
	require.Equal(t, byte(0x01), document[4], "Expected double type code")
	require.Equal(t, byte('o'), document[5], "Expected 'o' from 'ok' field name")
	require.Equal(t, byte('k'), document[6], "Expected 'k' from 'ok' field name")
	require.Equal(t, byte(0x00), document[7], "Expected null terminator")

	// next 8 bytes should be a double with value 1.0
	expectedValue := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F}
	require.Equal(t, expectedValue, document[8:16], "Expected double value 1.0")

	// doc should end with a null byte
	require.Equal(t, byte(0x00), document[16], "Expected document terminator")
}
