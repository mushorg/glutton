package producer

import (
	"reflect"
)

// maxSanitizeDepth bounds recursion into nested decoded values.
const maxSanitizeDepth = 16

// SanitizeDecoded returns a deep copy of decoded with sanitizer applied to
// every string and []byte it contains: struct fields (exported), slice and
// array elements, map keys and values, and values behind pointers and
// interfaces. Handlers store attacker-visible addresses in many fields (SIP
// from/to, OPC UA endpoint_url, ...), so scrubbing only payload and path
// would leak the sensor address. The input is never modified.
func SanitizeDecoded(decoded interface{}, sanitizer func([]byte) []byte) interface{} {
	if decoded == nil || sanitizer == nil {
		return decoded
	}
	return sanitizeValue(reflect.ValueOf(decoded), sanitizer, 0).Interface()
}

func sanitizeValue(v reflect.Value, sanitizer func([]byte) []byte, depth int) reflect.Value {
	if depth > maxSanitizeDepth {
		return v
	}
	switch v.Kind() {
	case reflect.String:
		out := reflect.New(v.Type()).Elem()
		out.SetString(string(sanitizer([]byte(v.String()))))
		return out
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			out := reflect.New(v.Type()).Elem()
			out.SetBytes(sanitizer(v.Bytes()))
			return out
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(sanitizeValue(v.Index(i), sanitizer, depth+1))
		}
		return out
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return v // fixed-size IDs (SPIs, GUIDs); replacement could change the length
		}
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(sanitizeValue(v.Index(i), sanitizer, depth+1))
		}
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := 0; i < v.NumField(); i++ {
			if f := out.Field(i); f.CanSet() {
				f.Set(sanitizeValue(v.Field(i), sanitizer, depth+1))
			}
		}
		return out
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(sanitizeValue(v.Elem(), sanitizer, depth+1))
		return out
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(sanitizeValue(v.Elem(), sanitizer, depth+1))
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(sanitizeValue(iter.Key(), sanitizer, depth+1), sanitizeValue(iter.Value(), sanitizer, depth+1))
		}
		return out
	}
	return v
}
