//go:build !darwin

package clientinfo

func executablePath(int) string { return "" }
