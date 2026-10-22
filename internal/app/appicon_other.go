//go:build !darwin

package app

func setBundleIcon(bundle string, icns []byte) bool { return true }
