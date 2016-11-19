package glutton

import (
	"fmt"
	"os"
)

// CheckError handles Fatal errors
func CheckError(msg string, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "[*] Fatal Error.", err.Error())
		os.Exit(1)
	}
}
