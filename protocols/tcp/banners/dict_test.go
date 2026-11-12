package banners

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDICTGreeting(t *testing.T) {
	origNow, origPID := now, dictPID
	now = func() time.Time { return time.Unix(1794504358, 0) }
	dictPID = func() int { return 4171 }
	t.Cleanup(func() { now, dictPID = origNow, origPID })

	resp, ok := ForPort(2628)
	require.True(t, ok)
	require.Equal(t, "dict", resp.Name)
	require.True(t, resp.ServerFirst)
	require.True(t, resp.FollowUpEach)
	require.Equal(t, "220 ubuntu dictd 1.12.1/rf on Linux 5.15.0-91-generic <auth.mime> <4171.0.1794504358@ubuntu>\r\n", string(resp.Data))

	// nmap-service-probes NULL match for dictd
	nmap := regexp.MustCompile(`^220 ([-.\w]+) dictd ([-.\w/]+) on ([-.+ \w]+) <auth\.mime>`)
	m := nmap.FindStringSubmatch(string(resp.Data))
	require.NotNil(t, m)
	require.Equal(t, []string{"ubuntu", "1.12.1/rf", "Linux 5.15.0-91-generic"}, m[1:])
}

func TestDICTFollowUp(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Response
	}{
		{"crlf crlf", "\r\n\r\n", Response{Name: "dict-unknown", Data: []byte(dictUnknown + dictUnknown)}},
		{"bare LF", "\n", Response{Name: "dict-unknown", Data: []byte(dictUnknown)}},
		{"unknown verb", "HELP\r\n", Response{Name: "dict-unknown", Data: []byte(dictUnknown)}},
		{"client", "CLIENT nmap\r\n", Response{Name: "dict-ok", Data: []byte(dictOK)}},
		{"quit", "quit\r\n", Response{Name: "dict-bye", Close: true, Data: []byte(dictBye)}},
		{"stops at quit", "QUIT\r\nHELP\r\n", Response{Name: "dict-bye", Close: true, Data: []byte(dictBye)}},
		{"unterminated", "DEFINE * test", Response{Name: "dict", NoReply: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := DICTFollowUp([]byte(tc.in))
			require.True(t, ok)
			require.Equal(t, tc.want, got)
		})
	}
}
