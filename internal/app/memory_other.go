//go:build !darwin

package app

func residentMemory() int64 { return 0 }
