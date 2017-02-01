package glutton

import (
	"io/ioutil"
	"os"
	"path/filepath"

	log "github.com/Sirupsen/logrus"
	"github.com/kung-foo/freki"
	uuid "github.com/satori/go.uuid"
)

// Glutton struct
type Glutton struct {
	Logger *log.Logger
	ID     uuid.UUID
}

// Event is a struct for glutton events
type Event struct {
	SrcHost  string     `json:"srcHost"`
	SrcPort  string     `json:"srcPort"`
	DstPort  string     `json:"dstPort"`
	SensorID string     `json:"sensorID"`
	Rule     freki.Rule `json:"-"`
}

func (g *Glutton) makeID() error {
	dirName := "/var/lib/glutton"
	fileName := "glutton.id"
	filePath := filepath.Join(dirName, fileName)
	err := os.MkdirAll(dirName, 0644)
	if err != nil {
		return err
	}
	if f, err := os.OpenFile(filePath, os.O_RDWR, 0644); os.IsNotExist(err) {
		g.ID = uuid.NewV4()
		errWrite := ioutil.WriteFile(filePath, g.ID.Bytes(), 0644)
		if err != nil {
			return errWrite
		}
	} else {
		if err != nil {
			return err
		}
		buff, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}
		g.ID, err = uuid.FromBytes(buff)
		if err != nil {
			return err
		}
	}
	return nil
}

// New creates a new Glutton instance
func New() (g *Glutton, err error) {
	g = &Glutton{}
	g.makeID()
	return
}
