package app

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/egoist/mygo"
)

type windowStates string

func (d windowStates) path() string { return filepath.Join(string(d), "window-state.json") }

func (d windowStates) LoadWindowStates() (map[string]mygo.WindowState, error) {
	data, err := os.ReadFile(d.path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var states map[string]mygo.WindowState
	if err := json.Unmarshal(data, &states); err != nil {
		return nil, err
	}
	return states, nil
}

func (d windowStates) SaveWindowStates(states map[string]mygo.WindowState) error {
	data, err := json.Marshal(states, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	tmp := d.path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, d.path())
}
