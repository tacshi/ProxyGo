//go:build !darwin

package clientinfo

func bundleIdentifier(string) string { return "" }
