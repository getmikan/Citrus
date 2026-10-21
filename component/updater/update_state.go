package updater

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	C "github.com/metacubex/mihomo/constant"
)

type updateState struct {
	Sequences map[string]uint64 `json:"sequences"`
}

func updateStatePath() string { return C.Path.Resolve("update-state.json") }

func loadUpdateSequence(channel string) uint64 {
	data, err := os.ReadFile(updateStatePath())
	if err != nil {
		return 0
	}
	var state updateState
	if json.Unmarshal(data, &state) != nil {
		return 0
	}
	return state.Sequences[channel]
}

func saveUpdateSequence(channel string, sequence uint64) error {
	path := updateStatePath()
	if !C.Path.IsSafePath(path) {
		return C.Path.ErrNotSafePath(path)
	}
	state := updateState{Sequences: map[string]uint64{}}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &state)
	}
	if state.Sequences == nil {
		state.Sequences = map[string]uint64{}
	}
	if sequence <= state.Sequences[channel] {
		return errors.New("update sequence did not advance")
	}
	state.Sequences[channel] = sequence
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".update-state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
