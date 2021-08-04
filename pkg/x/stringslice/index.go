package stringslice

func Index(limit int, predicate func(i int) bool) int {
	for i := 0; i < limit; i++ {
		if predicate(i) {
			return i
		}
	}
	return -1
}

func IndexOf(arr []string, str string) int {
	return Index(len(arr), func(i int) bool {
		return arr[i] == str
	})
}
