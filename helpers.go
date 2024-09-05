package saml

// contains checks to see if haystack contains needle
func contains[T comparable](haystack []T, needle T) bool {
	for _, i := range haystack {
		if i == needle {
			return true
		}
	}
	return false
}
