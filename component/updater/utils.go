package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	mihomoHttp "github.com/metacubex/mihomo/component/http"

	"github.com/metacubex/http"
)

const defaultHttpTimeout = time.Second * 90

// downloadForBytes fetches url into memory, failing with a
// *utils.SizeLimitError when the body is larger than limit bytes.
func downloadForBytes(url string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultHttpTimeout)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, errors.New(resp.Status)
	}

	buf, err := utils.ReadAllLimit(resp.Body, limit)
	if err != nil {
		var limitErr *utils.SizeLimitError
		if errors.As(err, &limitErr) {
			err = fmt.Errorf("response %w", err)
		}
		return nil, err
	}
	return buf, nil
}

func saveFile(bytes []byte, path string) error {
	return os.WriteFile(path, bytes, 0o644)
}
