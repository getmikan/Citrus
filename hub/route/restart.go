package route

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func restartRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/", restart)
	return r
}

// restartUnsupported, when set, is why the core cannot re-execute itself.
var restartUnsupported string

// SetRestartUnsupported makes POST /restart and POST /upgrade refuse with
// reason instead of starting a process that cannot load its configuration
// (one read from stdin, which the new process gets already consumed).
func SetRestartUnsupported(reason string) {
	restartUnsupported = reason
}

// refuseRestart answers 409 and reports true when the core cannot restart.
func refuseRestart(w http.ResponseWriter, r *http.Request) bool {
	if restartUnsupported == "" {
		return false
	}
	render.Status(r, http.StatusConflict)
	render.JSON(w, r, newError("restart unavailable: "+restartUnsupported))
	return true
}

func restart(w http.ResponseWriter, r *http.Request) {
	if refuseRestart(w, r) {
		return
	}
	// modify from https://github.com/AdguardTeam/AdGuardHome/blob/595484e0b3fb4c457f9bb727a6b94faa78a66c5f/internal/home/controlupdate.go#L108
	execPath, err := os.Executable()
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(fmt.Sprintf("getting path: %s", err)))
		return
	}

	render.JSON(w, r, render.M{"status": "ok"})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// modify from https://github.com/AdguardTeam/AdGuardHome/blob/595484e0b3fb4c457f9bb727a6b94faa78a66c5f/internal/home/controlupdate.go#L180
	// The background context is used because the underlying functions wrap it
	// with timeout and shut down the server, which handles current request.  It
	// also should be done in a separate goroutine for the same reason.
	go restartExecutable(execPath)
}

func restartExecutable(execPath string) {
	var err error
	executor.Shutdown()
	if runtime.GOOS == "windows" {
		cmd := exec.Command(execPath, os.Args[1:]...)
		log.Infoln("restarting: %q %q", execPath, os.Args[1:])
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Start()
		if err != nil {
			log.Fatalln("restarting: %s", err)
		}

		os.Exit(0)
	}

	log.Infoln("restarting: %q %q", execPath, os.Args[1:])
	err = syscall.Exec(execPath, os.Args, os.Environ())
	if err != nil {
		log.Fatalln("restarting: %s", err)
	}
}
