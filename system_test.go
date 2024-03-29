package glutton

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCountOpenFiles(t *testing.T) {
	openFiles, err := countOpenFiles()
	require.NoError(t, err, "failed to count open files")
	require.NotEmpty(t, openFiles, "unexpected number of open files")
}

func TestCountRunningRoutines(t *testing.T) {
	runningRoutines := runtime.NumGoroutine()
	require.NotEmpty(t, runningRoutines, "expected running routines")
}
