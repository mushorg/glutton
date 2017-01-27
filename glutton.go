package glutton

import (
	log "github.com/Sirupsen/logrus"
)

// Glutton struct
type Glutton struct {
	Logger *log.Logger
}

// New creates a new Glutton instance
func New() *Glutton {
	return &Glutton{}
}
