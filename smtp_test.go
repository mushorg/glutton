package glutton

import (
	"testing"
)

func TestValidateMail(t *testing.T) {

	if validateMail("MAIL FROM:<example@example.com>") != true {
		t.Fatal("Validate email regex failed")
	}

	if validateMail("MAIL FROM:<example.com>") == true {
		t.Fatal("Validate email regex failed")
	}
}

func TestValidateRCPT(t *testing.T) {

	if validateRCPT("RCPT TO:<example@example.com>") != true {
		t.Fatal(validateRCPT("Validate rcpt regex failed"))
	}

	if validateRCPT("RCPT TO:<example.com>") == true {
		t.Fatal(validateRCPT("Validate rcpt regex failed"))
	}
}
