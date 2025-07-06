package spicy

/*
#cgo CXXFLAGS: -I/opt/spicy/include -I${SRCDIR}/parsers -std=c++17 -fPIC -O3 -DNDEBUG -fvisibility=hidden
#cgo LDFLAGS:  -L/opt/spicy/lib -lspicy-rt -lhilti-rt -lz -lpthread -ldl "-Wl,-rpath,/opt/spicy/lib"
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/mushorg/glutton/protocols/interfaces"
)

type workerCmdKind int8

const (
	cmdInitAndList workerCmdKind = iota + 1
	cmdParse
	cmdShutdown
)

type workerCmd struct {
	kind      workerCmdKind
	parser    string
	data      []byte
	replyChan chan any
}

var (
	workerOnce sync.Once
	cmdCh      chan workerCmd
)

func startWorker() {
	workerOnce.Do(func() {
		cmdCh = make(chan workerCmd)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			for cmd := range cmdCh {
				switch cmd.kind {
				case cmdInitAndList:
					C.spicy_init()

					cnt := C.int(0)
					pp := C.spicy_list_parsers(&cnt)
					list := []string{}
					if pp != nil && cnt > 0 {
						ptrs := (*[1 << 30]*C.char)(unsafe.Pointer(pp))[:cnt:cnt]
						for _, p := range ptrs {
							list = append(list, C.GoString(p))
						}
						C.spicy_free_parser_list(pp, cnt)
					}
					cmd.replyChan <- list

				case cmdParse:
					cn := C.CString(cmd.parser)
					cres := C.spicy_parse_generic(
						cn,
						(*C.uchar)(unsafe.Pointer(&cmd.data[0])),
						C.int(len(cmd.data)),
					)
					C.free(unsafe.Pointer(cn))
					cmd.replyChan <- cres

				case cmdShutdown:
					var err error
					func() {
						defer func() {
							if r := recover(); r != nil {
								err = fmt.Errorf("panic during cleanup: %v", r)
							}
						}()
						C.spicy_cleanup()
					}()
					cmd.replyChan <- err
					close(cmd.replyChan)
					return
				}
			}
		}()
	})
}

var (
	initOnce          sync.Once
	registeredParsers = make(map[string]string)
	parsersMutex      sync.RWMutex
)

func Initialize(logger interfaces.Logger) {
	initOnce.Do(func() {
		startWorker()

		resp := make(chan any, 1)
		cmdCh <- workerCmd{kind: cmdInitAndList, replyChan: resp}
		names := (<-resp).([]string)

		if C.spicy_is_initialized() == 0 {
			logger.Error("failed to initialise Spicy runtime")
			return
		}
		logger.Info("Spicy runtime initialised successfully")

		parsersMutex.Lock()
		for _, raw := range names {
			raw = strings.TrimSpace(raw)

			if raw == "" || !strings.Contains(raw, "::") {
				continue
			}

			parts := strings.SplitN(raw, "::", 2)
			proto := strings.ToLower(strings.TrimSpace(parts[0]))
			canonical := strings.TrimSpace(raw)

			if _, ok := registeredParsers[proto]; !ok {
				registeredParsers[proto] = canonical
				logger.Info("registered Spicy parser", "protocol", proto, "parser", canonical)
			}
		}
		parsersMutex.Unlock()
	})
}

type ParsedData struct {
	Protocol string                 `json:"protocol"`
	Fields   map[string]interface{} `json:"fields"`
	Error    error                  `json:"-"`
}

func Parse(proto string, data []byte) (*ParsedData, error) {
	parsersMutex.RLock()
	name, ok := registeredParsers[strings.ToLower(proto)]
	parsersMutex.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no Spicy parser registered for %q", proto)
	}
	name = strings.TrimSpace(name)

	if len(data) == 0 {
		return nil, errors.New("input data is empty")
	}

	resp := make(chan any, 1)
	cmdCh <- workerCmd{kind: cmdParse, parser: name, data: data, replyChan: resp}
	raw := <-resp
	if raw == nil {
		return nil, errors.New("Spicy parse failed: no response received")
	}
	cRes, ok := raw.(*C.ParsedData)
	if !ok {
		return nil, errors.New("internal type assertion failed")
	}
	defer C.spicy_free_parsed_data(cRes)

	out := &ParsedData{Protocol: proto, Fields: map[string]interface{}{}}
	if cRes.error_message != nil {
		err := errors.New(C.GoString(cRes.error_message))
		out.Error = err
		return out, err
	}

	if cRes.fields != nil && cRes.field_count > 0 {
		fs := (*[1 << 30]C.ParsedField)(unsafe.Pointer(cRes.fields))[:cRes.field_count:cRes.field_count]
		for _, f := range fs {
			k := C.GoString(f.name)
			if f.is_binary != 0 {
				out.Fields[k] = C.GoBytes(unsafe.Pointer(f.value), f.length)
			} else {
				out.Fields[k] = C.GoString(f.value)
			}
		}
	}
	return out, nil
}

func Cleanup() error {
	resp := make(chan any, 1)
	cmdCh <- workerCmd{kind: cmdShutdown, replyChan: resp}
	if v := <-resp; v != nil {
		return v.(error)
	}
	return nil
}
