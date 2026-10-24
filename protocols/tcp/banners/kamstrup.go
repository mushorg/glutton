package banners

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
)

// Kamstrup Meter Protocol (KMP) over TCP, the tcp/1025 service of Kamstrup
// 382 / OMNIPOWER electricity meters. A request frame is 0x80, the meter
// address, a command ID, data, a CRC-16/CCITT (XMODEM) of address..data and
// 0x0D; a response starts with 0x40 instead. Bytes 06 0D 1B 40 80 between the
// start and stop bytes are stuffed as 1B <byte^FF>. Framing, register units
// and the login command follow Conpot's kamstrup_meter (GPL-2.0, reimplemented
// here); the readings are this meter's own, since Conpot's template values
// identify Conpot.

const (
	kmpRequestStart  = 0x80
	kmpResponseStart = 0x40
	kmpStop          = 0x0d
	kmpEscape        = 0x1b
	kmpAddress       = 0x3f // meter address Shodan and Metertool use
	kmpGetRegister   = 0x10
	kmpLogin         = 0x92
	kmpLoginDenied   = 0x01
)

// kmpRegister is the unit code, value length and SiEx byte (bit 7 sign of
// the value, bit 6 sign of the exponent, bits 0-5 the decimal exponent) the
// meter reports for a register.
type kmpRegister struct {
	unit, length, siex byte
}

const (
	kmpKWh   = 2
	kmpVolt  = 33
	kmpDeci  = 0x41 // x 10^-1
	kmpMicro = 0x44 // x 10^-4
)

// kmpRegisters are the registers Shodan's KMP probe reads (Ochi event
// 66cc9166-1cdd-4596-9d6a-c92c291fbc4a). Others are left out of the reply.
var kmpRegisters = map[uint16]kmpRegister{
	0x0001: {kmpKWh, 4, kmpDeci},  // active energy import
	0x0002: {kmpKWh, 4, kmpDeci},  // active energy export
	0x000d: {kmpKWh, 4, kmpMicro}, // active energy import, high resolution
	0x000e: {kmpKWh, 4, kmpMicro}, // active energy export, high resolution
	0x041e: {kmpVolt, 2, 0},       // voltage L1
	0x041f: {kmpVolt, 2, 0},       // voltage L2
}

// kmpMeter is the household meter behind the port: counters in 0.1 Wh that
// grow with a steady load from the time the process started.
type kmpMeter struct {
	start  time.Time
	imp    uint64 // import at start, 0.1 Wh
	exp    uint64 // export at start, 0.1 Wh
	loadW  uint64
	jitter func(n int) int // voltage noise, replaced in tests
}

var kmpPersona = &kmpMeter{
	start:  time.Now(),
	imp:    uint64(8000+rand.IntN(27000)) * 10000,
	exp:    uint64(rand.IntN(50)) * 10000,
	loadW:  uint64(300 + rand.IntN(300)),
	jitter: rand.IntN,
}

// value is the raw register value at t, scaled by the register's SiEx.
func (m *kmpMeter) value(reg uint16, t time.Time) uint64 {
	imp := m.imp + m.loadW*uint64(max(t.Sub(m.start).Milliseconds(), 0))/360000
	switch reg {
	case 0x0001:
		return imp / 1000
	case 0x0002:
		return m.exp / 1000
	case 0x000d:
		return imp
	case 0x000e:
		return m.exp
	}
	return uint64(226 + m.jitter(10))
}

func kmpCRC(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func kmpStuffed(b byte) bool {
	switch b {
	case 0x06, kmpStop, kmpEscape, kmpResponseStart, kmpRequestStart:
		return true
	}
	return false
}

// kmpFrames returns the address..data bytes of each request frame in data.
// It only matches when data is nothing but complete frames with valid CRCs,
// as a client sends them (Shodan pipelines several in one segment).
func kmpFrames(data []byte) ([][]byte, bool) {
	var frames [][]byte
	for len(data) > 0 {
		end := bytes.IndexByte(data, kmpStop)
		if data[0] != kmpRequestStart || end < 0 {
			return nil, false
		}
		var body []byte
		for i := 1; i < end; i++ {
			b := data[i]
			if b == kmpEscape {
				if i++; i == end {
					return nil, false
				}
				b = data[i] ^ 0xff
			}
			body = append(body, b)
		}
		n := len(body) - 2
		if n < 2 || kmpCRC(body[:n]) != binary.BigEndian.Uint16(body[n:]) {
			return nil, false
		}
		frames = append(frames, body[:n])
		data = data[end+1:]
	}
	return frames, len(frames) > 0
}

// kmpFrame wraps address..data in a response frame.
func kmpFrame(body []byte) []byte {
	body = binary.BigEndian.AppendUint16(body, kmpCRC(body))
	frame := []byte{kmpResponseStart}
	for _, b := range body {
		if kmpStuffed(b) {
			frame = append(frame, kmpEscape, b^0xff)
		} else {
			frame = append(frame, b)
		}
	}
	return append(frame, kmpStop)
}

// kmpRegisterReply answers a GetRegister body (count, then BE u16 IDs) with
// ID, unit, length, SiEx and the BE value for each known register.
func kmpRegisterReply(m *kmpMeter, body []byte, t time.Time) ([]byte, bool) {
	if len(body) < 1 || len(body) != 1+2*int(body[0]) {
		return nil, false
	}
	reply := []byte{kmpAddress, kmpGetRegister}
	for i := 1; i < len(body); i += 2 {
		id := binary.BigEndian.Uint16(body[i:])
		reg, ok := kmpRegisters[id]
		if !ok {
			continue
		}
		reply = binary.BigEndian.AppendUint16(reply, id)
		reply = append(reply, reg.unit, reg.length, reg.siex)
		v := m.value(id, t)
		for shift := int(reg.length-1) * 8; shift >= 0; shift -= 8 {
			reply = append(reply, byte(v>>shift))
		}
	}
	return kmpFrame(reply), true
}

// kmpAnswer answers the request frames in data: GetRegister with readings,
// login (a BE u16 PIN) with "denied". Frames for another address or command
// get no reply, but the connection stays open as on Conpot.
func kmpAnswer(m *kmpMeter, data []byte, t time.Time) (Response, bool) {
	frames, ok := kmpFrames(data)
	if !ok {
		return Response{}, false
	}
	resp := Response{Name: "kamstrup"}
	var pins []string
	for _, f := range frames {
		if f[0] != kmpAddress {
			continue
		}
		switch body := f[2:]; f[1] {
		case kmpGetRegister:
			if reply, ok := kmpRegisterReply(m, body, t); ok {
				resp.Data = append(resp.Data, reply...)
				if resp.Name == "kamstrup" {
					resp.Name = "kamstrup-getregister"
				}
			}
		case kmpLogin:
			if len(body) == 2 {
				pins = append(pins, strconv.Itoa(int(binary.BigEndian.Uint16(body))))
				resp.Data = append(resp.Data, kmpFrame([]byte{kmpAddress, kmpLogin, kmpLoginDenied})...)
				resp.Name = "kamstrup-login"
			}
		}
	}
	resp.Password = strings.Join(pins, ",")
	resp.NoReply = len(resp.Data) == 0
	return resp, true
}

func kamstrupReply(data []byte) (Response, bool) {
	return kmpAnswer(kmpPersona, data, now())
}
