package glutton

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/kung-foo/freki"
	"github.com/mushorg/glutton/producer"
	uuid "github.com/satori/go.uuid"
)

const gluttonServer = 5000

// Glutton struct
type Glutton struct {
	logger    *log.Logger
	id        uuid.UUID
	processor *freki.Processor

	address *producer.Address
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
		g.id = uuid.NewV4()
		errWrite := ioutil.WriteFile(filePath, g.id.Bytes(), 0644)
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
		g.id, err = uuid.FromBytes(buff)
		if err != nil {
			return err
		}
	}
	return nil
}

// New creates a new Glutton instance
func New(processor *freki.Processor, log *log.Logger, logHTTP *string) (g *Glutton, err error) {
	g = &Glutton{}
	g.makeID()
	g.processor = processor
	g.logger = log
	g.address = &producer.Address{
		Logger:   log,
		HTTPAddr: logHTTP,
	}
	return
}

// Start this is the main listener for rewritten package
func (g *Glutton) Start() {
	g.processor.AddServer(freki.NewUserConnServer(gluttonServer))
	g.processor.RegisterConnHandler("glutton", func(conn net.Conn, md *freki.Metadata) error {
		host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if md == nil {
			g.logger.Debugf("[glutton ] connection not tracked: %s:%s", host, port)
			return nil
		}

		g.logger.Debugf("[glutton ] new connection: %s:%s -> %d", host, port, uint(md.TargetPort))

		addr := *g.address.HTTPAddr
		if addr != "" {
			err := g.address.LogHTTP(addr, host, port, md.TargetPort.String(), g.id.String(), md.Rule.String())
			if err != nil {
				g.logger.Error(err)
			}
		}
		if md.Rule.Name == "telnet" {
			go g.HandleTelnet(conn)
		} else if md.TargetPort == 25 {
			go g.HandleSMTP(conn)
		} else if md.TargetPort == 3389 {
			go g.HandleRDP(conn)
		} else if md.TargetPort == 445 {
			go g.HandleSMB(conn)
		} else if md.TargetPort == 21 {
			go g.HandleFTP(conn)
		} else if md.TargetPort == 5060 {
			go g.HandleSIP(conn)
		} else if md.TargetPort == 5900 {
			go g.HandleRFB(conn)
		} else {
			snip, bufConn, err := g.Peek(conn, 4)
			g.OnErrorClose(err, conn)
			httpMap := map[string]bool{"GET ": true, "POST": true, "HEAD": true, "OPTI": true}
			if _, ok := httpMap[strings.ToUpper(string(snip))]; ok == true {
				go g.HandleHTTP(bufConn)
			} else {
				go g.HandleTCP(bufConn)
			}

		}
		return nil
	})
}

func (g *Glutton) OnErrorExit(err error) {
	if err != nil {
		g.logger.Fatalf("[glutton ] %+v", err)
	}
}

func (g *Glutton) OnErrorClose(err error, conn net.Conn) {
	if err != nil {
		g.logger.Error(err)
		err = conn.Close()
		if err != nil {
			g.logger.Error(err)
		}
	}
}
