package producer

import (
	"reflect"
)

// SanitizeDecoded copies a slice of handler frames and runs sanitizer on each
// Payload []byte and Path string field when those names exist.
func SanitizeDecoded(decoded interface{}, sanitizer func([]byte) []byte) interface{} {
	if decoded == nil || sanitizer == nil {
		return decoded
	}
	v := reflect.ValueOf(decoded)
	if v.Kind() != reflect.Slice {
		return decoded
	}
	n := v.Len()
	out := reflect.MakeSlice(v.Type(), n, n)
	for i := 0; i < n; i++ {
		item := v.Index(i)
		cp := reflect.New(item.Type()).Elem()
		cp.Set(item)
		if f := cp.FieldByName("Payload"); f.IsValid() && f.CanSet() && f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.Uint8 {
			f.SetBytes(sanitizer(f.Bytes()))
		}
		if f := cp.FieldByName("Path"); f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
			f.SetString(string(sanitizer([]byte(f.String()))))
		}
		out.Index(i).Set(cp)
	}
	return out.Interface()
}
