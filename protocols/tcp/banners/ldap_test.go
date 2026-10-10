package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// rootDSESearch is an anonymous root DSE search as sent by nmap ldap-rootdse:
// messageID 1, base "", scope baseObject, filter (objectClass=*), no attributes.
var rootDSESearch = append([]byte{
	0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20,
	0x04, 0x00, // baseObject ""
	0x0a, 0x01, 0x00, // scope baseObject
	0x0a, 0x01, 0x00, // derefAliases never
	0x02, 0x01, 0x00, // sizeLimit
	0x02, 0x01, 0x00, // timeLimit
	0x01, 0x01, 0x00, // typesOnly
	0x87, 0x0b, // present
}, append([]byte("objectClass"), 0x30, 0x00)...)

func TestMGLNDDProbe(t *testing.T) {
	// Ochi event 326742f1-0f6b-42c7-891f-c01081fc0166 (tcp/389)
	for _, p := range []string{"MGLNDD_1.2.3.4_389\n", "MGLNDD_1.2.3.4_389\r\n", "MGLNDD_1.2.3.4_389"} {
		resp, ok := ForPayload([]byte(p))
		require.True(t, ok, p)
		require.Equal(t, Response{Name: "mglndd", Silent: true}, resp)
	}
	for _, p := range []string{"MGLNDD_1.2.3.4_389\nGET / HTTP/1.0\r\n", "MGLNDD_1.2.3.4_\n", "xMGLNDD_1.2.3.4_389\n"} {
		_, ok := ForPayload([]byte(p))
		require.False(t, ok, p)
	}
}

func TestLDAPRootDSEQuery(t *testing.T) {
	msgID, ok := ldapRootDSEQuery(rootDSESearch)
	require.True(t, ok)
	require.Equal(t, []byte{0x01}, msgID)

	// long-form outer length and a two-byte messageID
	long := append([]byte{0x30, 0x81, 0x26, 0x02, 0x02, 0x01, 0x2c}, rootDSESearch[5:]...)
	msgID, ok = ldapRootDSEQuery(long)
	require.True(t, ok)
	require.Equal(t, []byte{0x01, 0x2c}, msgID)

	nonBase := append([]byte{}, rootDSESearch...)
	nonBase[11] = 0x02 // scope wholeSubtree
	named := append([]byte{0x30, 0x27, 0x02, 0x01, 0x01, 0x63, 0x22, 0x04, 0x02, 'd', 'c'}, rootDSESearch[9:]...)
	bind := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
	for _, data := range [][]byte{
		nil, []byte("MGLNDD_1.2.3.4_389\n"), rootDSESearch[:20], nonBase, named, bind,
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, // length past the data
		{0x30, 0x80, 0x00, 0x00},             // indefinite length
	} {
		_, ok := ldapRootDSEQuery(data)
		require.False(t, ok, "% x", data)
	}
}

func TestLDAPRootDSEReply(t *testing.T) {
	resp, ok := ForPayload(rootDSESearch)
	require.True(t, ok)
	require.Equal(t, "ldap-rootdse", resp.Name)
	require.False(t, resp.Silent)

	// SearchResultEntry for "" with every root DSE attribute
	tag, msg, rest, ok := berTLV(resp.Data)
	require.True(t, ok)
	require.Equal(t, byte(0x30), tag)
	require.NotZero(t, resp.Data[1]&0x80, "entry needs a long-form length")
	tag, id, msg, ok := berTLV(msg)
	require.True(t, ok)
	require.Equal(t, byte(0x02), tag)
	require.Equal(t, []byte{0x01}, id)
	tag, entry, msg, ok := berTLV(msg)
	require.True(t, ok)
	require.Equal(t, byte(0x64), tag)
	require.Empty(t, msg)
	tag, dn, entry, ok := berTLV(entry)
	require.True(t, ok)
	require.Equal(t, byte(0x04), tag)
	require.Empty(t, dn)
	tag, attrs, entry, ok := berTLV(entry)
	require.True(t, ok)
	require.Equal(t, byte(0x30), tag)
	require.Empty(t, entry)
	got := map[string][]string{}
	for len(attrs) > 0 {
		var attr, name, set []byte
		_, attr, attrs, ok = berTLV(attrs)
		require.True(t, ok)
		_, name, attr, ok = berTLV(attr)
		require.True(t, ok)
		tag, set, _, ok = berTLV(attr)
		require.True(t, ok)
		require.Equal(t, byte(0x31), tag)
		for len(set) > 0 {
			var v []byte
			_, v, set, ok = berTLV(set)
			require.True(t, ok)
			got[string(name)] = append(got[string(name)], string(v))
		}
	}
	require.Equal(t, []string{"top", "OpenLDAProotDSE"}, got["objectClass"])
	require.Equal(t, []string{"3"}, got["supportedLDAPVersion"])
	require.Len(t, got, len(rootDSE))

	// SearchResultDone success under the same messageID
	require.Equal(t, []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}, rest)
}
