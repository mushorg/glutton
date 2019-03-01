package glutton

import (
	"testing"
)

func TestCountOpenFiles(t *testing.T) {
	if countOpenFiles() < 0 {
		t.Fatalf("countOpenFiles returned %d, expected > 0", countOpenFiles())
	}
}

func TestCountRunningRoutines(t *testing.T) {
	if countRunningRoutines() < 0 {
		t.Fatalf("countOpenFiles returned %d, expected > 0", countOpenFiles())
	}
}
