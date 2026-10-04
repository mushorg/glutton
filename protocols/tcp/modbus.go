package tcp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"

	"github.com/xiegeo/modbusone"
)

const maxModbusMessages = 64

var modbusFunctionNames = map[modbusone.FunctionCode]string{
	modbusone.FcReadCoils:              "ReadCoils",
	modbusone.FcReadDiscreteInputs:     "ReadDiscreteInputs",
	modbusone.FcReadHoldingRegisters:   "ReadHoldingRegisters",
	modbusone.FcReadInputRegisters:     "ReadInputRegisters",
	modbusone.FcWriteSingleCoil:        "WriteSingleCoil",
	modbusone.FcWriteSingleRegister:    "WriteSingleRegister",
	modbusone.FcWriteMultipleCoils:     "WriteMultipleCoils",
	modbusone.FcWriteMultipleRegisters: "WriteMultipleRegisters",
}

type parsedModbus struct {
	Direction    string `json:"direction,omitempty"`
	FunctionCode string `json:"function_code,omitempty"`
	UnitID       uint8  `json:"unit_id,omitempty"`
	Address      uint16 `json:"address,omitempty"`
	Quantity     uint16 `json:"quantity,omitempty"`
	Payload      []byte `json:"payload,omitempty"`
}

type modbusServer struct {
	events   []parsedModbus
	conn     net.Conn
	logger   interfaces.Logger
	handler  modbusone.ProtocolHandler
	coils    map[uint16]bool
	discrete map[uint16]bool
	holding  map[uint16]uint16
	input    map[uint16]uint16
}

func modbusFunctionName(fc modbusone.FunctionCode) string {
	isErr, base := fc.SeparateError()
	if isErr {
		return "Exception"
	}
	if name, ok := modbusFunctionNames[base]; ok {
		return name
	}
	return "UNKNOWN"
}

func readBools(m map[uint16]bool, address, quantity uint16) ([]bool, error) {
	if err := modbusRangeOK(address, quantity); err != nil {
		return nil, err
	}
	out := make([]bool, quantity)
	for i := uint16(0); i < quantity; i++ {
		out[i] = m[address+i]
	}
	return out, nil
}

func writeBools(m map[uint16]bool, address uint16, values []bool) error {
	if err := modbusRangeOK(address, uint16(len(values))); err != nil {
		return err
	}
	for i, v := range values {
		m[address+uint16(i)] = v
	}
	return nil
}

func readRegs(m map[uint16]uint16, address, quantity uint16) ([]uint16, error) {
	if err := modbusRangeOK(address, quantity); err != nil {
		return nil, err
	}
	out := make([]uint16, quantity)
	for i := uint16(0); i < quantity; i++ {
		out[i] = m[address+i]
	}
	return out, nil
}

func writeRegs(m map[uint16]uint16, address uint16, values []uint16) error {
	if err := modbusRangeOK(address, uint16(len(values))); err != nil {
		return err
	}
	for i, v := range values {
		m[address+uint16(i)] = v
	}
	return nil
}

func modbusRangeOK(address, quantity uint16) error {
	if quantity == 0 {
		return modbusone.EcIllegalDataValue
	}
	if uint32(address)+uint32(quantity) > 0x10000 {
		return modbusone.EcIllegalDataAddress
	}
	return nil
}

func (s *modbusServer) read() ([]byte, error) {
	data := make([]byte, modbusone.MBAPHeaderLength+modbusone.MaxPDUSize)
	if _, err := io.ReadFull(s.conn, data[:modbusone.TCPHeaderLength]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}

	if data[2] != 0 || data[3] != 0 {
		return nil, fmt.Errorf("MBAP protocol of %X %X is unknown", data[2], data[3])
	}

	l := int(data[4])*256 + int(data[5])
	if l <= 2 {
		return nil, fmt.Errorf("MBAP data length of %v is too short", l)
	}
	if len(data) < l+modbusone.TCPHeaderLength {
		return nil, fmt.Errorf("MBAP data length of %v is too long", l)
	}
	n, err := io.ReadFull(s.conn, data[modbusone.TCPHeaderLength:l+modbusone.TCPHeaderLength])
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}

	adu := make([]byte, n+modbusone.TCPHeaderLength)
	copy(adu, data[:n+modbusone.TCPHeaderLength])
	return adu, nil
}

func parsedFromRequest(direction string, adu []byte, req, wire modbusone.PDU) parsedModbus {
	frame := parsedModbus{
		Direction:    direction,
		FunctionCode: modbusFunctionName(wire.GetFunctionCode()),
		Payload:      adu,
	}
	if len(adu) > modbusone.TCPHeaderLength {
		frame.UnitID = adu[modbusone.TCPHeaderLength]
	}
	if len(req) >= 3 {
		frame.Address = req.GetAddress()
		if qty, err := req.GetRequestCount(); err == nil {
			frame.Quantity = qty
		}
	}
	return frame
}

func (s *modbusServer) recordRead(adu []byte, p modbusone.PDU) {
	s.events = append(s.events, parsedFromRequest("read", adu, p, p))
}

func (s *modbusServer) write(req []byte, pdu modbusone.PDU) error {
	l := len(pdu) + 1
	bs := make([]byte, len(pdu)+modbusone.MBAPHeaderLength)
	n := modbusone.MBAPHeaderLength
	if len(req) < n {
		n = len(req)
	}
	copy(bs, req[:n])
	bs[4] = byte(l / 256)
	bs[5] = byte(l)
	copy(bs[modbusone.MBAPHeaderLength:], pdu)
	if _, err := s.conn.Write(bs); err != nil {
		return err
	}
	var reqPDU modbusone.PDU
	if len(req) > modbusone.MBAPHeaderLength {
		reqPDU = modbusone.PDU(req[modbusone.MBAPHeaderLength:])
	}
	s.events = append(s.events, parsedFromRequest("write", bs, reqPDU, pdu))
	return nil
}

func (s *modbusServer) writeError(req []byte, pdu modbusone.PDU, err error) {
	if werr := s.write(req, modbusone.ExceptionReplyPacket(pdu, modbusone.ToExceptionCode(err))); werr != nil {
		s.logger.Error("Failed to write Modbus exception reply", slog.String("protocol", "modbus"), producer.ErrAttr(werr))
	}
}

func newModbusServer(conn net.Conn, logger interfaces.Logger) *modbusServer {
	s := &modbusServer{
		events:   []parsedModbus{},
		conn:     conn,
		logger:   logger,
		coils:    map[uint16]bool{},
		discrete: map[uint16]bool{},
		holding:  map[uint16]uint16{},
		input:    map[uint16]uint16{},
	}
	s.handler = &modbusone.SimpleHandler{
		ReadDiscreteInputs: func(address, quantity uint16) ([]bool, error) {
			logger.Debug("ReadDiscreteInputs", slog.String("protocol", "modbus"), slog.Uint64("address", uint64(address)), slog.Uint64("quantity", uint64(quantity)))
			return readBools(s.discrete, address, quantity)
		},
		WriteDiscreteInputs: func(address uint16, values []bool) error {
			logger.Debug("WriteDiscreteInputs", slog.String("protocol", "modbus"), slog.Uint64("address", uint64(address)), slog.Int("quantity", len(values)))
			return writeBools(s.discrete, address, values)
		},
		ReadCoils: func(address, quantity uint16) ([]bool, error) {
			logger.Debug("ReadCoils", slog.String("protocol", "modbus"), slog.Uint64("address", uint64(address)), slog.Uint64("quantity", uint64(quantity)))
			return readBools(s.coils, address, quantity)
		},
		WriteCoils: func(address uint16, values []bool) error {
			logger.Debug("WriteCoils", slog.String("protocol", "modbus"), slog.Uint64("address", uint64(address)), slog.Int("quantity", len(values)))
			return writeBools(s.coils, address, values)
		},
		ReadInputRegisters: func(address, quantity uint16) ([]uint16, error) {
			logger.Debug("ReadInputRegisters", slog.String("protocol", "modbus"), slog.Uint64("address", uint64(address)), slog.Uint64("quantity", uint64(quantity)))
			return readRegs(s.input, address, quantity)
		},
		WriteInputRegisters: func(address uint16, values []uint16) error {
			logger.Debug("WriteInputRegisters", slog.String("protocol", "modbus"), slog.Uint64("address", uint64(address)), slog.Int("quantity", len(values)))
			return writeRegs(s.input, address, values)
		},
		ReadHoldingRegisters: func(address, quantity uint16) ([]uint16, error) {
			logger.Debug("ReadHoldingRegisters", slog.String("protocol", "modbus"), slog.Uint64("address", uint64(address)), slog.Uint64("quantity", uint64(quantity)))
			return readRegs(s.holding, address, quantity)
		},
		WriteHoldingRegisters: func(address uint16, values []uint16) error {
			logger.Debug("WriteHoldingRegisters", slog.String("protocol", "modbus"), slog.Uint64("address", uint64(address)), slog.Int("quantity", len(values)))
			return writeRegs(s.holding, address, values)
		},
		OnErrorImp: func(req modbusone.PDU, errRep modbusone.PDU) {
			logger.Debug("Modbus error PDU", slog.String("protocol", "modbus"), slog.String("request", fmt.Sprintf("%x", req)), slog.String("error", fmt.Sprintf("%x", errRep)))
		},
	}
	return s
}

func HandleModbus(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := newModbusServer(conn, logger)

	defer func() {
		if err := h.ProduceTCP("modbus", conn, md, helpers.FirstOrEmpty[parsedModbus](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "modbus"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close Modbus connection", slog.String("protocol", "modbus"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	for i := 0; i < maxModbusMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "modbus"), producer.ErrAttr(err))
			return nil
		}
		data, err := server.read()
		if err != nil {
			if err != io.EOF {
				logger.Debug("Failed to read data", slog.String("protocol", "modbus"), producer.ErrAttr(err))
			}
			break
		}
		if len(data) <= modbusone.MBAPHeaderLength {
			continue
		}

		p := modbusone.PDU(data[modbusone.MBAPHeaderLength:])
		server.recordRead(data, p)

		logger.Info(
			"Modbus request",
			slog.String("handler", "modbus"),
			slog.String("protocol", "modbus"),
			slog.String("src_ip", host),
			slog.String("src_port", port),
			slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
			slog.String("function_code", modbusFunctionName(p.GetFunctionCode())),
		)

		if err := p.ValidateRequest(); err != nil {
			server.writeError(data, p, err)
			continue
		}

		fc := p.GetFunctionCode()
		switch {
		case fc.IsReadToServer():
			values, err := server.handler.OnRead(p)
			if err != nil {
				server.writeError(data, p, err)
				continue
			}
			if err := server.write(data, p.MakeReadReply(values)); err != nil {
				logger.Error("Failed to write to connection", slog.String("protocol", "modbus"), producer.ErrAttr(err))
				return nil
			}
		case fc.IsWriteToServer():
			values, err := p.GetRequestValues()
			if err != nil {
				server.writeError(data, p, err)
				continue
			}
			if err := server.handler.OnWrite(p, values); err != nil {
				server.writeError(data, p, err)
				continue
			}
			if err := server.write(data, p.MakeWriteReply()); err != nil {
				logger.Error("Failed to write to connection", slog.String("protocol", "modbus"), producer.ErrAttr(err))
				return nil
			}
		default:
			server.writeError(data, p, modbusone.EcIllegalFunction)
		}
	}

	return nil
}
