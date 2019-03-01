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

	desiredString := formatRequest(mockReq)
	obtainedString:= "GET http://example.com HTTP/1.1\nHost: example.com"

	if desiredString!=obtainedString{
		t.Fatalf("desired request is %s but request obtained is %s",desiredString,obtainedString)
	}
}
