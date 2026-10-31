package ipopts

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func ethernetIPv4TCP(ipOpts []byte, srcPort, dstPort uint16, flags uint8, truncateIP bool) []byte {
	if (20+len(ipOpts))%4 != 0 {
		panic("ip options must be 4-byte padded")
	}
	ihlWords := (20 + len(ipOpts)) / 4
	ihl := ihlWords * 4
	totalLen := ihl + 20 // minimal TCP header, no payload
	ip := make([]byte, totalLen)
	ip[0] = byte(0x40 | ihlWords) // version 4 + IHL
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	ip[8] = 64 // TTL
	ip[9] = 6  // TCP
	copy(ip[12:16], net.IPv4(203, 0, 113, 10).To4())
	copy(ip[16:20], net.IPv4(192, 0, 2, 10).To4())
	copy(ip[20:], ipOpts)
	tcp := ip[ihl:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4 // data offset 5 (20 bytes)
	tcp[13] = flags

	// Manual 14-byte Ethernet header (SerializeTo alone pads to 60 bytes).
	eth := make([]byte, 14)
	copy(eth[0:6], net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	copy(eth[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(eth[12:14], uint16(layers.EthernetTypeIPv4))
	frame := append(eth, ip...)
	if truncateIP {
		// Keep Ethernet + part of IP so totalLen claims more than captured.
		return frame[:14+ihl+10]
	}
	return frame
}

func TestDecodeSYNWithRR(t *testing.T) {
	// RR: type 7, length 7, pointer 4, one empty slot + pad to 4 bytes → length must be multiple of...
	// Use NOP padding: RR (type=7,len=7,ptr=4, 4 bytes addr space) + NOP = 8 bytes.
	ipOpts := []byte{
		7, 7, 4, 0, 0, 0, 0, // RR
		1, // NOP
	}
	raw := ethernetIPv4TCP(ipOpts, 54321, 80, tcpSYN, false)
	pkt, ok := Decode(raw, layers.LinkTypeEthernet)
	require.True(t, ok)
	require.Equal(t, "203.0.113.10", pkt.SrcIP.String())
	require.Equal(t, "192.0.2.10", pkt.DstIP.String())
	require.EqualValues(t, 54321, pkt.SrcPort)
	require.EqualValues(t, 80, pkt.DstPort)
	require.Equal(t, "SYN", pkt.Frame.Command)
	require.False(t, pkt.Frame.Malformed)
	require.False(t, pkt.Frame.Truncated)
	require.Len(t, pkt.Frame.Options, 2)
	require.Equal(t, uint8(7), pkt.Frame.Options[0].Type)
	require.Equal(t, "RR", pkt.Frame.Options[0].Name)
	require.Equal(t, uint8(7), pkt.Frame.Options[0].Length)
	require.Equal(t, "NOP", pkt.Frame.Options[1].Name)
	require.NotEmpty(t, pkt.Frame.Payload)
}

func TestDecodeSYNACKWithTS(t *testing.T) {
	// Timestamp: type 68, length 8, overflow/flag + timestamp (minimal) + pad with NOPs to 8? length 8 means 6 data bytes.
	ipOpts := []byte{
		68, 8, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, // TS
	}
	raw := ethernetIPv4TCP(ipOpts, 80, 54321, tcpSYN|tcpACK, false)
	pkt, ok := Decode(raw, layers.LinkTypeEthernet)
	require.True(t, ok)
	require.Equal(t, "SYN-ACK", pkt.Frame.Command)
	require.Equal(t, "TS", pkt.Frame.Options[0].Name)
	require.Equal(t, []byte{0x0f, 0x01, 0x02, 0x03, 0x04, 0x05}, pkt.Frame.Options[0].Data)
}

func TestDecodeMalformedOptionLength(t *testing.T) {
	ipOpts := []byte{
		7, 1, // RR with illegal length 1
		0, 0, // pad
	}
	raw := ethernetIPv4TCP(ipOpts, 1, 2, tcpSYN, false)
	pkt, ok := Decode(raw, layers.LinkTypeEthernet)
	require.True(t, ok)
	require.True(t, pkt.Frame.Malformed)
	require.NotEmpty(t, pkt.Frame.Options)
	require.Equal(t, uint8(7), pkt.Frame.Options[0].Type)
	require.EqualValues(t, 1, pkt.Frame.Options[0].Length)
}

func TestDecodeTruncated(t *testing.T) {
	ipOpts := []byte{
		1, 1, 1, 1, // NOPs
	}
	raw := ethernetIPv4TCP(ipOpts, 9, 10, tcpACK, true)
	pkt, ok := Decode(raw, layers.LinkTypeEthernet)
	require.True(t, ok)
	require.True(t, pkt.Frame.Truncated)
	// Truncation cuts inside the TCP header, so flags are missing.
	require.True(t, pkt.Frame.Malformed)
	require.Empty(t, pkt.Frame.Command)
}

func TestDecodeVLAN(t *testing.T) {
	ipOpts := []byte{1, 1, 1, 1}
	ihlWords := (20 + len(ipOpts)) / 4
	ihl := ihlWords * 4
	totalLen := ihl + 20
	ip := make([]byte, totalLen)
	ip[0] = byte(0x40 | ihlWords)
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	ip[9] = 6
	copy(ip[12:16], net.IPv4(1, 2, 3, 4).To4())
	copy(ip[16:20], net.IPv4(5, 6, 7, 8).To4())
	copy(ip[20:], ipOpts)
	tcp := ip[ihl:]
	binary.BigEndian.PutUint16(tcp[0:2], 1111)
	binary.BigEndian.PutUint16(tcp[2:4], 2222)
	tcp[12] = 5 << 4
	tcp[13] = tcpSYN

	// eth (14) + 802.1Q (4) + IPv4
	raw := make([]byte, 0, 18+len(ip))
	raw = append(raw, 0x02, 0, 0, 0, 0, 2) // dst
	raw = append(raw, 0x02, 0, 0, 0, 0, 1) // src
	raw = append(raw, 0x81, 0x00)          // EtherType Dot1Q
	raw = append(raw, 0x00, 0x00)          // VLAN TCI
	raw = append(raw, 0x08, 0x00)          // encapsulated IPv4
	raw = append(raw, ip...)

	pkt, ok := Decode(raw, layers.LinkTypeEthernet)
	require.True(t, ok)
	require.Equal(t, "1.2.3.4", pkt.SrcIP.String())
	require.EqualValues(t, 1111, pkt.SrcPort)
	require.EqualValues(t, 2222, pkt.DstPort)
}

func TestDecodeNoOptionsRejected(t *testing.T) {
	raw := ethernetIPv4TCP(nil, 1, 2, tcpSYN, false)
	_, ok := Decode(raw, layers.LinkTypeEthernet)
	require.False(t, ok)
}

func TestDecodeFlagCommands(t *testing.T) {
	cases := []struct {
		flags uint8
		want  string
	}{
		{tcpSYN, "SYN"},
		{tcpSYN | tcpACK, "SYN-ACK"},
		{tcpACK, "ACK"},
		{tcpRST, "RST"},
		{tcpRST | tcpACK, "RST"},
		{tcpFIN, "FIN"},
		{tcpFIN | tcpACK, "FIN-ACK"},
		{tcpPSH | tcpACK, "PSH-ACK"},
		{tcpSYN | tcpFIN | tcpACK, "flags=0x13"},
	}

	ipOpts := []byte{1, 1, 1, 1}
	for _, tc := range cases {
		raw := ethernetIPv4TCP(ipOpts, 1, 2, tc.flags, false)
		pkt, ok := Decode(raw, layers.LinkTypeEthernet)
		require.True(t, ok, "flags=%#x", tc.flags)
		require.Equal(t, tc.want, pkt.Frame.Command, "flags=%#x", tc.flags)
	}
}

func TestDecodeLinuxSLL(t *testing.T) {
	ipOpts := []byte{1, 1, 1, 1}
	ihlWords := (20 + len(ipOpts)) / 4
	ihl := ihlWords * 4
	totalLen := ihl + 20
	ip := make([]byte, totalLen)
	ip[0] = byte(0x40 | ihlWords)
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	ip[9] = 6
	copy(ip[12:16], net.IPv4(9, 9, 9, 9).To4())
	copy(ip[16:20], net.IPv4(8, 8, 8, 8).To4())
	copy(ip[20:], ipOpts)
	tcp := ip[ihl:]
	binary.BigEndian.PutUint16(tcp[0:2], 4000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4
	tcp[13] = tcpSYN

	// Linux cooked capture header: 16 bytes, protocol at offset 14 = IPv4 (0x0800).
	sll := make([]byte, 16)
	binary.BigEndian.PutUint16(sll[14:16], uint16(layers.EthernetTypeIPv4))
	raw := append(sll, ip...)

	pkt, ok := Decode(raw, layers.LinkTypeLinuxSLL)
	require.True(t, ok)
	require.Equal(t, "9.9.9.9", pkt.SrcIP.String())
	require.EqualValues(t, 4000, pkt.SrcPort)
	require.EqualValues(t, 443, pkt.DstPort)
}

func TestOptionNameUnknown(t *testing.T) {
	require.Equal(t, "99", optionName(99))
	require.Equal(t, "RTRALT", optionName(148))
}
