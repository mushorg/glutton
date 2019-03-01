package glutton

import (
	"testing"
)

func TestCountOpenFiles(t *testing.T) {
	openFiles := countOpenFiles()
	if openFiles <= 0 {
		t.Fatalf("countOpenFiles returned %d, expected > 0", openFiles)
	}
}

func TestCountRunningRoutines(t *testing.T) {
	runningRoutines := countRunningRoutines()
	if runningRoutines <= 0 {
		t.Fatalf("countOpenFiles returned %d, expected > 0", runningRoutines)
	}
}
