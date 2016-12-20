package glutton

import (
	"log"
	"os"
)

// CheckError handles Fatal errors
func CheckError(msg string, err error) {
	if err != nil {
		log.Printf("Fatal Error: %s", err.Error())
		os.Exit(1)
	}
}
