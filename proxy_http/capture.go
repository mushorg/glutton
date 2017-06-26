package proxy_http

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Header struct {
	http.Header
}

type Response struct {
	ID            uint      `json:"id,omitempty"`
	Origin        string    `json:"origin"`
	Method        string    `json:"method"`
	Status        int       `json:"status"`
	ContentType   string    `json:"content_type"`
	ContentLength uint      `json:"content_length"`
	Host          string    `json:"host"`
	URL           string    `json:"url"`
	Scheme        string    `json:"scheme"`
	Path          string    `json:"path"`
	Header        Header    `json:"header,omitempty"`
	Body          []byte    `json:"body,omitempty"`
	RequestHeader Header    `json:"request_header,omitempty"`
	RequestBody   []byte    `json:"request_body,omitempty"`
	DateStart     time.Time `json:"date_start"`
	DateEnd       time.Time `json:"date_end"`
	TimeTaken     int64     `json:"time_taken"`
}

type captureWriteCloser struct {
	r *http.Response
	c chan Response
	s time.Time
	bytes.Buffer
}

func (cwc *captureWriteCloser) Close() error {
	reqbody := bytes.NewBuffer(nil)

	if cwc.r.Request.Body != nil {
		io.Copy(reqbody, cwc.r.Request.Body)
		cwc.r.Request.Body.Close()
	}

	now := time.Now()
	r := Response{
		Origin:        cwc.r.Request.RemoteAddr,
		Method:        cwc.r.Request.Method,
		Status:        cwc.r.StatusCode,
		ContentType:   http.DetectContentType(cwc.Bytes()),
		ContentLength: uint(cwc.Len()),
		Host:          cwc.r.Request.URL.Host,
		URL:           cwc.r.Request.URL.String(),
		Scheme:        cwc.r.Request.URL.Scheme,
		Path:          cwc.r.Request.URL.Path,
		Header:        Header{cwc.r.Header},
		Body:          cwc.Bytes(),
		RequestHeader: Header{cwc.r.Request.Header},
		RequestBody:   reqbody.Bytes(),
		DateStart:     cwc.s,
		DateEnd:       now,
		TimeTaken:     now.UnixNano() - cwc.s.UnixNano(),
	}

	cwc.c <- r

	return nil
}

type capture struct {
	c chan Response
}

func New(c chan Response) *capture {
	return &capture{c: c}
}

func (c *capture) NewWriteCloser(res *http.Response) (io.WriteCloser, error) {
	return &captureWriteCloser{r: res, c: c.c, s: time.Now()}, nil
}

func chunk(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// Log prints a standard log string to the system.
func log(pr *ProxiedRequest) (string, error) {

	line := []string{
		chunk(pr.Request.RemoteAddr),
		chunk(""),
		chunk(""),
		chunk("\"" + fmt.Sprintf("%s %s %s", pr.Request.Method, pr.Request.URL, pr.Request.Proto) + "\""),
		chunk(fmt.Sprintf("%d", pr.Response.StatusCode)),
		chunk(fmt.Sprintf("%d", pr.Response.ContentLength)),
	}

	return strings.Join(line, " "), nil
}
