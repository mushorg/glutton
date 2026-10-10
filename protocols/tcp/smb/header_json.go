package smb

import (
	"encoding/binary"
	"encoding/json"
)

// NTStatus returns the SMB1 NT status code as a uint32.
func NTStatus(h SMBHeader) uint32 {
	return binary.LittleEndian.Uint32(h.Status[:])
}

// StatusName maps well-known SMB1 NT status codes to names.
func StatusName(h SMBHeader) string {
	switch NTStatus(h) {
	case 0:
		return "STATUS_SUCCESS"
	case statusNotImplemented:
		return "STATUS_NOT_IMPLEMENTED"
	case statusInvalidParameter:
		return "STATUS_INVALID_PARAMETER"
	case statusBadNetworkName:
		return "STATUS_BAD_NETWORK_NAME"
	case binary.LittleEndian.Uint32(statusInsuffServerResources[:]):
		return "STATUS_INSUFF_SERVER_RESOURCES"
	default:
		return ""
	}
}

func (h SMBHeader) MarshalJSON() ([]byte, error) {
	pid := uint32(binary.LittleEndian.Uint16(h.PIDLow[:])) | uint32(binary.LittleEndian.Uint16(h.PIDHigh[:]))<<16
	view := struct {
		Protocol   string `json:"protocol,omitempty"`
		Command    byte   `json:"command,omitempty"`
		Status     uint32 `json:"status,omitempty"`
		StatusName string `json:"status_name,omitempty"`
		Flags      byte   `json:"flags,omitempty"`
		Flags2     string `json:"flags2,omitempty"`
		TID        uint16 `json:"tid,omitempty"`
		PID        uint32 `json:"pid,omitempty"`
		UID        uint16 `json:"uid,omitempty"`
		MID        uint16 `json:"mid,omitempty"`
	}{
		Protocol:   string(h.Protocol[:]),
		Command:    h.Command,
		Status:     NTStatus(h),
		StatusName: StatusName(h),
		Flags:      h.Flags,
		Flags2:     fmtFlags2(flags2(h)),
		TID:        binary.LittleEndian.Uint16(h.TID[:]),
		PID:        pid,
		UID:        binary.LittleEndian.Uint16(h.UID[:]),
		MID:        binary.LittleEndian.Uint16(h.MID[:]),
	}
	return json.Marshal(view)
}

func fmtFlags2(v uint16) string {
	if v == 0 {
		return ""
	}
	return "0x" + hex4(v)
}

func hex4(v uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{
		digits[v>>12&0xf],
		digits[v>>8&0xf],
		digits[v>>4&0xf],
		digits[v&0xf],
	})
}
