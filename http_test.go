package glutton

import (
	"net/http"
	"testing"
)

func TestFormatRequest(t *testing.T) {
	mockReq, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	obtainedString := formatRequest(mockReq)
	desiredString := "GET http://example.com HTTP/1.1\nHost: example.com"

	if obtainedString != desiredString {
		t.Fatalf("desired request is %s but request obtained is %s", desiredString, obtainedString)
	}
}
