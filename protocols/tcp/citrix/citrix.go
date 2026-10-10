// Package citrix recognizes Citrix ADC / NetScaler Gateway CVE-2019-19781
// requests and builds the replies of a vulnerable-looking appliance.
//
// The exploit chain is a path traversal from /vpn/ into /vpns/: scanners
// fetch /vpn/../vpns/cfg/smb.conf (or check for a 403 on /vpn/../vpns/),
// exploits POST a Template Toolkit payload in the "title" field to
// /vpn/../vpns/portal/scripts/newbm.pl (the bookmark file name rides in the
// NSC_USER header) and then GET /vpn/../vpns/portal/<file>.xml to render it.
// Stage handling follows MalwareTech/CitrixHoneypot and x1sec/citrix-honeypot.
package citrix

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	// MaxTemplate caps the decoded "title" payload; the raw request keeps it all.
	MaxTemplate = 4096
	// MaxNSCUser caps the NSC_USER header value.
	MaxNSCUser = 256
)

// Stage names the step of the CVE-2019-19781 chain a request belongs to.
type Stage string

const (
	StageLogin         Stage = "login"          // GET /vpn/index.html
	StageProbe         Stage = "probe"          // /vpn/../vpns/
	StageSMBConf       Stage = "smb_conf"       // /vpn/../vpns/cfg/smb.conf
	StageTemplateWrite Stage = "template_write" // POST /vpn/../vpns/portal/scripts/newbm.pl
	StageTemplateFetch Stage = "template_fetch" // GET /vpn/../vpns/portal/<file>.xml
	StageTraversal     Stage = "traversal"      // any other /vpns/ traversal
)

// Request is the Citrix-specific part of a decoded HTTP read frame. It never
// carries credentials: newbm.pl takes no password.
type Request struct {
	Stage     Stage  `json:"stage"`
	NSCUser   string `json:"nsc_user,omitempty"`  // bookmark file name (often a ../ traversal)
	Template  string `json:"template,omitempty"`  // newbm.pl "title" field, the injected template
	Truncated bool   `json:"truncated,omitempty"` // NSCUser or Template hit its cap
}

// Classify returns the stage for a request, or "" when it is not Citrix.
// escapedPath is the request path as sent; %2e%2e and %2f are decoded first.
func Classify(method, escapedPath string) Stage {
	decoded, err := url.PathUnescape(escapedPath)
	if err != nil {
		decoded = escapedPath
	}
	if !hasDotDot(decoded) {
		switch decoded {
		case "/vpn", "/vpn/", "/vpn/index.html":
			return StageLogin
		}
		return ""
	}
	cleaned := path.Clean(decoded)
	switch {
	case cleaned == "/vpns":
		return StageProbe
	case cleaned == "/vpns/cfg/smb.conf":
		return StageSMBConf
	case cleaned == "/vpns/portal/scripts/newbm.pl" && method == http.MethodPost:
		return StageTemplateWrite
	case strings.HasPrefix(cleaned, "/vpns/portal/") && strings.HasSuffix(cleaned, ".xml"):
		return StageTemplateFetch
	case strings.HasPrefix(cleaned, "/vpns/"):
		return StageTraversal
	}
	return ""
}

func hasDotDot(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// Inspect classifies a request and, for the template write, extracts the
// NSC_USER header and the "title" form field. It returns nil for non-Citrix
// requests. header may be nil when the caller has no parsed headers.
func Inspect(method, escapedPath string, header http.Header, body []byte) *Request {
	stage := Classify(method, escapedPath)
	if stage == "" {
		return nil
	}
	req := &Request{Stage: stage}
	if stage != StageTemplateWrite {
		return req
	}
	if header != nil {
		req.NSCUser, req.Truncated = capString(header.Get("NSC_USER"), MaxNSCUser)
	}
	if form, err := url.ParseQuery(string(body)); err == nil {
		var cut bool
		req.Template, cut = capString(form.Get("title"), MaxTemplate)
		req.Truncated = req.Truncated || cut
	}
	return req
}

func capString(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	return s[:n], true
}

// Respond builds the reply for a stage. It returns nil for "".
func Respond(stage Stage) []byte {
	switch stage {
	case StageLogin:
		return response("200 OK", "text/html; charset=UTF-8", loginPage)
	case StageProbe:
		return response("403 Forbidden", "text/html; charset=iso-8859-1", forbiddenPage)
	case StageSMBConf:
		return response("200 OK", "text/plain; charset=UTF-8", smbConf)
	case StageTemplateWrite:
		// Best guess at the newbm.pl success page: it reloads the portal frame.
		return response("200 OK", "text/html; charset=UTF-8", bookmarkAdded)
	case StageTemplateFetch, StageTraversal:
		// No rendered template and no fake command output.
		return response("200 OK", "text/html; charset=UTF-8", "")
	}
	return nil
}

func response(status, contentType, body string) []byte {
	return []byte(fmt.Sprintf("HTTP/1.1 %s\r\n"+
		"Server: Apache\r\n"+
		"X-Frame-Options: SAMEORIGIN\r\n"+
		"X-XSS-Protection: 1; mode=block\r\n"+
		"X-Content-Type-Options: nosniff\r\n"+
		"Content-Type: %s\r\n"+
		"Content-Length: %d\r\n"+
		"\r\n%s", status, contentType, len(body), body))
}

const smbConf = "[global]\n" +
	"\tencrypt passwords = yes\n" +
	"\tname resolve order = lmhosts wins host bcast\n"

const forbiddenPage = `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /vpns/
on this server.<br />
</p>
</body></html>
`

const bookmarkAdded = `<html><body><script language="javascript">parent.window.ns_reload();</script></body></html>
`

const loginPage = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<title>NetScaler Gateway</title>
<link rel="SHORTCUT ICON" href="/vpn/images/AccessGateway.ico" type="image/vnd.microsoft.icon" />
</head>
<body class="ns_login_body">
<form method="post" action="/cgi/login" name="vpnForm" autocomplete="off">
<div id="logonbox-innerbox">
<span id="logonbox-title">Please log on</span>
<label for="login">User name</label>
<input type="text" id="login" name="login" class="prePopulatedCredentials" size="30" maxlength="127" />
<label for="passwd">Password</label>
<input type="password" id="passwd" name="passwd" size="30" maxlength="127" />
<input type="submit" id="nsg-x1-logon-button" value="Log On" />
</div>
</form>
</body>
</html>
`
