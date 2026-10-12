package itp

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func sampleV043() *U {
	u := &U{
		Layout:      LayoutV043,
		Sequence:    42,
		PacTyp:      1,
		Version:     43,
		DelX:        [2]int32{10, -10},
		DelY:        [2]int32{5, 0},
		DelZ:        [2]int32{-3, 7},
		DelYaw:      [2]int32{1, 2},
		DelPitch:    [2]int32{3, 4},
		DelRoll:     [2]int32{5, 6},
		ButtonState: [2]int32{1, 0},
		Grasp:       [2]int32{32767, -32768},
		SurgeonMode: SurgeonEngaged,
	}
	u.Checksum = u.ExpectedChecksum()
	return u
}

func TestParseV043RoundTrip(t *testing.T) {
	u := sampleV043()
	b := u.Marshal()
	require.Len(t, b, SizeV043)
	// sequence 42, pactyp 1, version 43, little-endian
	require.Equal(t, "2a00000001000000"+"2b000000", hex.EncodeToString(b[:12]))

	got, err := Parse(b)
	require.NoError(t, err)
	require.Equal(t, u, got)
	// 1 + (10-10) + (5+0) + (-3+7) + 1 + 0 + 42
	require.Equal(t, int32(53), got.ExpectedChecksum())
}

func TestParseRaven2RoundTrip(t *testing.T) {
	u := &U{
		Layout:      LayoutRaven2,
		Sequence:    7,
		PacTyp:      1,
		Version:     1,
		DelX:        [2]int32{100, 200},
		Qx:          [2]float64{0.5, -0.5},
		Qw:          [2]float64{1, 1},
		Grasp:       [2]int32{-1, 1},
		SurgeonMode: SurgeonDisengaged,
		Checksum:    999,
	}
	b := u.Marshal()
	require.Len(t, b, SizeRaven2)
	got, err := Parse(b)
	require.NoError(t, err)
	require.Equal(t, u, got)
	require.NotEqual(t, got.Checksum, got.ExpectedChecksum())
}

func TestParseRejectsOtherSizes(t *testing.T) {
	for _, n := range []int{0, 4, SizeV, SizeV043 - 1, SizeV043 + 1, SizeRaven2 + 1} {
		_, err := Parse(make([]byte, n))
		require.ErrorIs(t, err, ErrSize, "size %d", n)
	}
}

func TestBuildReply(t *testing.T) {
	v := BuildReply(sampleV043(), 3)
	b := v.Marshal()
	require.Len(t, b, SizeV)
	got, err := ParseV(b)
	require.NoError(t, err)
	require.Equal(t, v, got)
	require.Equal(t, uint32(3), got.Sequence)
	require.Equal(t, uint32(42), got.LastSequence)
	require.Equal(t, uint32(1), got.PacTyp)
	require.Equal(t, uint32(43), got.Version)
	require.Equal(t, int32(RunlevelPedalD), got.Runlevel)
	require.Equal(t, int32(RunlevelPedalD+3), got.Checksum)

	u := sampleV043()
	u.SurgeonMode = SurgeonDisengaged
	require.Equal(t, int32(RunlevelPedalU), BuildReply(u, 1).Runlevel)

	_, err = ParseV(b[:SizeV-1])
	require.ErrorIs(t, err, ErrSize)
}

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		name     string
		last     uint32
		seen     bool
		cur      uint32
		status   string
		nextLast uint32
	}{
		{"zero reflects", 5, true, 0, SeqReflect, 5},
		{"zero first", 0, false, 0, SeqReflect, 0},
		{"first", 0, false, 500, SeqNew, 500},
		{"valid", 5, true, 6, SeqValid, 6},
		{"skipped", 5, true, 9, SeqSkipped, 9},
		{"duplicate", 5, true, 5, SeqDuplicate, 5},
		{"reset", 5000, true, 10, SeqReset, 10},
		{"out of sequence", 5000, true, 4500, SeqOutOfOrder, 5000},
		{"small last behind", 5, true, 2, SeqOutOfOrder, 5},
		{"max uint32", 0xfffffffe, true, 0xffffffff, SeqValid, 0xffffffff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, next := Classify(tc.last, tc.seen, tc.cur)
			require.Equal(t, tc.status, status)
			require.Equal(t, tc.nextLast, next)
		})
	}
}

func TestRunlevelName(t *testing.T) {
	require.Equal(t, "E_STOP", RunlevelName(RunlevelEStop))
	require.Equal(t, "PEDAL_DN", RunlevelName(RunlevelPedalD))
	require.Equal(t, "RL_9", RunlevelName(9))
}
