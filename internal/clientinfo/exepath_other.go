//go:build !darwin

package clientinfo

func executablePath(int) string { return "" }

func processPath(int) string { return "" }
