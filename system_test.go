package glutton

import (
	"testing"
)

func TestCountOpenFiles(t *testing.T) {
	if !(countOpenFiles() > 0) {
		t.Fatal("countOpenFiles return an unexpected value")
	}
}

func TestCountRunningRoutines(t *testing.T) {

	if !(countRunningRoutines() > 0) {
		t.Fatal("countRunningRoutines return an unexpected value")
	}
}
