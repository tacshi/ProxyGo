//go:build !darwin

package certs

import "errors"

var errNoKeychain = errors.New("keychain: only available on macOS")

type keychain struct{}

func (keychain) Set(string, string) error { return errNoKeychain }

func (keychain) Get(string) (string, error) { return "", errNoKeychain }

func (keychain) Delete(string) error { return nil }
