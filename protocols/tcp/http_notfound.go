package tcp

import (
	"fmt"
	"strings"
)

// httpNotFoundBody is a minimal HTML 404 page without a server signature.
const httpNotFoundBody = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n</body>\r\n</html>\r\n"

// httpNotFoundHead is the header block of httpNotFound; HEAD gets it alone.
var httpNotFoundHead = fmt.Sprintf(
	"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n",
	len(httpNotFoundBody),
)

// httpNotFound is the reply for crawler and browser asset paths that a bare
// server does not have. An empty 200 for these is a tell: Censys, Shodan and
// proxy-abusing crawlers fetch them on every host.
func httpNotFound(method string) []byte {
	if method == "HEAD" {
		return []byte(httpNotFoundHead)
	}
	return []byte(httpNotFoundHead + httpNotFoundBody)
}

// httpMissingPaths are exact (lowercased) paths answered with httpNotFound.
var httpMissingPaths = map[string]bool{
	"/favicon.ico":                true,
	"/sitemap.xml":                true,
	"/sitemap_index.xml":          true,
	"/ads.txt":                    true,
	"/app-ads.txt":                true,
	"/humans.txt":                 true,
	"/crossdomain.xml":            true,
	"/clientaccesspolicy.xml":     true,
	"/browserconfig.xml":          true,
	"/site.webmanifest":           true,
	"/manifest.json":              true,
	"/apple-app-site-association": true,
}

// isHTTPMissingPath reports whether path is a crawler/browser asset path
// (favicon, sitemap, /.well-known/*, apple-touch-icon) that gets a 404
// instead of the default reply.
func isHTTPMissingPath(path string) bool {
	p := strings.ToLower(path)
	if httpMissingPaths[p] {
		return true
	}
	if strings.HasPrefix(p, "/.well-known/") {
		return true
	}
	return strings.HasPrefix(p, "/apple-touch-icon") && strings.HasSuffix(p, ".png")
}
