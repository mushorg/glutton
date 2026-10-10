package citrix

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		method, path string
		want         Stage
	}{
		{"GET", "/vpn/index.html", StageLogin},
		{"GET", "/vpn/", StageLogin},
		{"GET", "/vpn/../vpns/", StageProbe},
		{"GET", "/vpn/%2e%2e/vpns/", StageProbe},
		{"GET", "/vpn/../vpns/cfg/smb.conf", StageSMBConf},
		{"GET", "/vpn/..%2Fvpns/cfg/smb.conf", StageSMBConf},
		{"GET", "/vpn/../vpns//cfg/smb.conf", StageSMBConf},
		{"POST", "/vpn/../vpns/portal/scripts/newbm.pl", StageTemplateWrite},
		{"GET", "/vpn/../vpns/portal/scripts/newbm.pl", StageTraversal},
		{"GET", "/vpn/../vpns/portal/aXJlZ2F.xml", StageTemplateFetch},
		{"GET", "/vpn/../vpns/portal/scripts/rmbm.pl", StageTraversal},
		{"GET", "/../vpns/cfg/smb.conf", StageSMBConf},
		// no traversal: not the vulnerable path
		{"GET", "/vpns/cfg/smb.conf", ""},
		{"POST", "/vpns/portal/scripts/newbm.pl", ""},
		{"GET", "/vpn/js/rdx/core/lang/rdx_en.json.gz", ""},
		{"GET", "/", ""},
		{"GET", "/a/../etc/passwd", ""},
		{"GET", "/vpn/%zz", ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			require.Equal(t, tt.want, Classify(tt.method, tt.path))
		})
	}
}

func TestInspectTemplateWrite(t *testing.T) {
	header := http.Header{}
	header.Set("NSC_USER", "../../../netscaler/portal/templates/aXJlZ2F")
	header.Set("NSC_NONCE", "nsroot")
	body := []byte("url=http://example.com&title=%5B%25+template.new%28%7B%27BLOCK%27%3D%27print+readpipe%28%22id%22%29%27%7D%29%25%5D&desc=desc&UI_inuse=a")

	got := Inspect("POST", "/vpn/../vpns/portal/scripts/newbm.pl", header, body)
	require.Equal(t, &Request{
		Stage:    StageTemplateWrite,
		NSCUser:  "../../../netscaler/portal/templates/aXJlZ2F",
		Template: `[% template.new({'BLOCK'='print readpipe("id")'})%]`,
	}, got)
}

func TestInspectCapsTemplate(t *testing.T) {
	header := http.Header{}
	header.Set("NSC_USER", strings.Repeat("a", MaxNSCUser+10))
	body := []byte("title=" + strings.Repeat("x", MaxTemplate+100))

	got := Inspect("POST", "/vpn/../vpns/portal/scripts/newbm.pl", header, body)
	require.Len(t, got.NSCUser, MaxNSCUser)
	require.Len(t, got.Template, MaxTemplate)
	require.True(t, got.Truncated)
}

func TestInspectNilHeaderAndOtherStages(t *testing.T) {
	got := Inspect("POST", "/vpn/../vpns/portal/scripts/newbm.pl", nil, []byte("title=abc"))
	require.Equal(t, &Request{Stage: StageTemplateWrite, Template: "abc"}, got)

	require.Equal(t, &Request{Stage: StageSMBConf}, Inspect("GET", "/vpn/../vpns/cfg/smb.conf", nil, nil))
	require.Nil(t, Inspect("GET", "/index.html", nil, nil))
}

func TestRespond(t *testing.T) {
	tests := []struct {
		stage    Stage
		status   int
		contains string
	}{
		{StageLogin, http.StatusOK, "<title>NetScaler Gateway</title>"},
		{StageProbe, http.StatusForbidden, "You don't have permission to access /vpns/"},
		{StageSMBConf, http.StatusOK, "[global]\n\tencrypt passwords = yes"},
		{StageTemplateWrite, http.StatusOK, "parent.window.ns_reload"},
		{StageTemplateFetch, http.StatusOK, ""},
		{StageTraversal, http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(string(tt.stage), func(t *testing.T) {
			raw := Respond(tt.stage)
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, tt.status, resp.StatusCode)
			require.Equal(t, "Apache", resp.Header.Get("Server"))
			// Content-Length must match the body exactly so keep-alive clients do not hang.
			require.EqualValues(t, len(body), resp.ContentLength)
			require.True(t, bytes.HasSuffix(raw, body))
			require.Contains(t, string(body), tt.contains)
		})
	}
	require.Nil(t, Respond(""))
}
