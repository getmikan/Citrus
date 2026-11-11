package xdrive

import (
	"context"
	"errors"
	"io"

	"github.com/metacubex/http"
)

var errNotFound = errors.New("object not found")

// A listing can contain many inline objects. Bound the whole response as well
// as individual segments, including responses from a misconfigured template.
func readResponse(r io.Reader) ([]byte, error) {
	const maxResponseBytes = 32 << 20
	b, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err == nil && len(b) > maxResponseBytes {
		return nil, newError("storage response too large")
	}
	return b, err
}

type Entry struct {
	Name   string
	Inline []byte
}
type Storage interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
	List(context.Context, string) ([]Entry, error)
	Close() error
}

func newStorage(c Config, client *http.Client) (Storage, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if client == nil {
		client = defaultHTTPClient(c)
	}
	switch c.Service {
	case "local":
		return newLocalStorage(c.RemoteFolder)
	case "google-drive", "Google Drive":
		return newDriveStorage(client, &c)
	default:
		return newTemplateStorage(client, &c)
	}
}
