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

// Glutton struct
type Glutton struct {
	logger    *log.Logger
	id        uuid.UUID
	processor *freki.Processor
	address   *producer.Address
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
	g.address = &producer.Address{log, logHTTP}
	return
}

// This is the main listener for rewritten package
func (gtn *Glutton) Start() {
	ln, err := net.Listen("tcp", ":5000")
	gtn.OnErrorExit(err)

	for {
		conn, err := ln.Accept()
		gtn.OnErrorExit(err)

		go func(conn net.Conn) {
			// TODO: Figure out how this works.
			//conn.SetReadDeadline(time.Now().Add(time.Second * 5))
			host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ck := freki.NewConnKeyByString(host, port)
			md := gtn.processor.Connections.GetByFlow(ck)
			if md == nil {
				gtn.logger.Debugf("[glutton ] connection not tracked: %s:%s", host, port)
				return
			}

			gtn.logger.Debugf("[glutton ] new connection: %s:%s -> %d", host, port, md.TargetPort)

			addr := *gtn.address.HTTPAddr
			if addr != "" {
				err = gtn.address.LogHTTP(addr, host, port, md.TargetPort.String(), gtn.id.String(), md.Rule.String())
				if err != nil {
					gtn.logger.Error(err)
				}
			}

			if md.Rule.Name == "telnet" {
				go gtn.HandleTelnet(conn)
			} else if md.TargetPort == 25 {
				go gtn.HandleSMTP(conn)
			} else if md.TargetPort == 3389 {
				go gtn.HandleRDP(conn)
			} else if md.TargetPort == 445 {
				go gtn.HandleSMB(conn)
			} else if md.TargetPort == 21 {
				go gtn.HandleFTP(conn)
			} else if md.TargetPort == 5060 {
				go gtn.HandleSIP(conn)
			} else if md.TargetPort == 5900 {
				go gtn.HandleRFB(conn)
			} else {
				snip, bufConn, err := gtn.Peek(conn, 4)
				gtn.OnErrorClose(err, conn)
				httpMap := map[string]bool{"GET ": true, "POST": true, "HEAD": true, "OPTI": true}
				if _, ok := httpMap[strings.ToUpper(string(snip))]; ok == true {
					go gtn.HandleHTTP(bufConn)
				} else {
					go gtn.HandleTCP(bufConn)
				}
			}
		}(conn)
	}
}

func (gtn *Glutton) OnErrorExit(err error) {
	if err != nil {
		gtn.logger.Fatalf("[glutton ] %+v", err)
	}
}

func (gtn *Glutton) OnErrorClose(err error, conn net.Conn) {
	if err != nil {
		gtn.logger.Error(err)
		err = conn.Close()
		if err != nil {
			gtn.logger.Error(err)
		}
	}
}
