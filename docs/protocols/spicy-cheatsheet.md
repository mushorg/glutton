# Spicy cheatsheet

This page covers only the Spicy concepts needed to work in this repository. For the language reference, use the upstream Spicy documentation.

## What Spicy Does Here

Glutton embeds the Spicy/HILTI runtime through cgo. The current bridge:

- initializes the runtime on a locked OS thread
- lists compiled parser modules
- registers parser keys from module names
- parses payload bytes through a generic entry point
- flattens returned HILTI values into `map[string]interface{}`

The Go side calls:

```go
parsed, err := spicy.Parse("http", payload)
```

The result has:

```go
type ParsedData struct {
	Protocol string                 `json:"protocol"`
	Fields   map[string]interface{} `json:"fields"`
	Error    error                  `json:"-"`
}
```

## Current Parsers

Current grammar files:

```text
protocols/spicy/parsers/http.spicy
protocols/spicy/parsers/tcp.spicy
```

Current registered parser modules:

| Spicy module/type | Go parser key | Purpose |
| --- | --- | --- |
| `HTTP::Request` | `http` | Parse HTTP request fields. |
| `TCP::Protocol` | `tcp` | Detect selected application protocols from raw TCP payload bytes. |

## Grammar Shape

A Spicy file declares a module and one or more units:

```spicy
module HTTP;

type Version = unit {
    :       /HTTP\//;
    number: /[0-9]+\.[0-9]*/;
};

public type Request = unit {
    method:  /[^ \t\r\n]+/;
    :        /[ \t]+/;
    version: Version;
};
```

The real HTTP grammar is richer than this example. Read `protocols/spicy/parsers/http.spicy` before changing HTTP parsing.

## Flattened Fields

The bridge flattens parser output into field names:

```text
method
uri.raw
uri.path
uri.query
version.number
headers[0].name
headers[0].value
body.content
```

Rules of thumb:

- nested unit fields become dotted names
- vectors become indexed names such as `headers[0].name`
- bytes may arrive in Go as strings or byte slices depending on bridge handling
- parser consumers should tolerate missing fields for malformed input

## Build Step

Run this after changing `.spicy` files:

```bash
export PATH=/opt/spicy/bin:$PATH
make spicy
```

The Spicy Makefile generates:

- `protocols/spicy/*.cc`
- `protocols/spicy/spicy_linker.cc`
- `protocols/spicy/parsers/*.h`

Those files are ignored by Git.

## Registration

At startup, `spicy.Initialize(...)` lists compiled parsers. Parser names that contain `::` are registered by lowercasing the module name before the first `::`.

Examples:

```text
HTTP::Request -> http
TCP::Protocol -> tcp
```

This is why Go calls `spicy.Parse("http", payload)` rather than `spicy.Parse("HTTP::Request", payload)`.

## No `.evt` Files Today

Some Spicy and Zeek documentation describes `.evt` event-translation files. Glutton's current repository does not include `.evt` files. It compiles `.spicy` grammar files and consumes parser output through the generic Go bridge.

## What Stays In Go

Keep these responsibilities in Go handlers:

- how much data to read
- connection deadlines
- handler routing
- process logs
- producer event shape
- fake service responses
- fallback behavior after parse failure
