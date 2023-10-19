package helpers

func FirstOrEmpty[T any](s []T) T {
	if len(s) > 0 {
		return s[0]
	}
	var t T
	return t
}
