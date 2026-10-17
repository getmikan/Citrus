package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/metacubex/mihomo/common/cmd"
	"github.com/metacubex/mihomo/component/age"
	_ "github.com/metacubex/mihomo/component/gcballast" // a server build: raise the GC heap goal
	"github.com/metacubex/mihomo/component/generator"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/updater"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/provider"

	"go.uber.org/automaxprocs/maxprocs"
)

var (
	version                       bool
	testConfig                    bool
	geodataMode                   bool
	homeDir                       string
	configFile                    string
	configString                  string
	configBytes                   []byte
	ageSecretKey                  string
	ageSecretKeyFile              string
	externalUI                    string
	externalController            string
	externalControllerTLS         string
	externalControllerUnix        string
	externalControllerPipe        string
	externalControllerRoutingMark int
	externalControllerInsecure    bool
	secret                        string
	secretFile                    string
	postUp                        string
	postDown                      string
)

func getIntEnv(key string) int {
	value := os.Getenv(key)
	intValue, _ := strconv.Atoi(value)
	return intValue
}

func getBoolEnv(key string) bool {
	value, _ := strconv.ParseBool(os.Getenv(key))
	return value
}

func init() {
	flag.StringVar(&homeDir, "d", os.Getenv("CLASH_HOME_DIR"), "set configuration directory")
	flag.StringVar(&configFile, "f", os.Getenv("CLASH_CONFIG_FILE"), "specify configuration file")
	flag.StringVar(&configString, "config", os.Getenv("CLASH_CONFIG_STRING"), "specify base64-encoded configuration string")
	flag.StringVar(&ageSecretKey, "age-secret-key", os.Getenv("CLASH_AGE_SECRET_KEY"), "specify age secret key to decrypt configuration")
	flag.StringVar(&ageSecretKeyFile, "age-secret-key-file", os.Getenv("CLASH_AGE_SECRET_KEY_FILE"), "read the age secret key to decrypt configuration from a file")
	flag.StringVar(&externalUI, "ext-ui", os.Getenv("CLASH_OVERRIDE_EXTERNAL_UI_DIR"), "override external ui directory")
	flag.StringVar(&externalController, "ext-ctl", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER"), "override external controller address")
	flag.StringVar(&externalControllerTLS, "ext-ctl-tls", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_TLS"), "override external controller tls address")
	flag.StringVar(&externalControllerUnix, "ext-ctl-unix", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX"), "override external controller unix address")
	flag.StringVar(&externalControllerPipe, "ext-ctl-pipe", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_PIPE"), "override external controller pipe address")
	flag.IntVar(&externalControllerRoutingMark, "ext-ctl-routing-mark", getIntEnv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_ROUTING_MARK"), "override external controller routing mark")
	flag.BoolVar(&externalControllerInsecure, "ext-ctl-allow-insecure", getBoolEnv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_ALLOW_INSECURE"), "allow the external controller on a non-loopback address without a secret")
	flag.StringVar(&secret, "secret", os.Getenv("CLASH_OVERRIDE_SECRET"), "override secret for RESTful API")
	flag.StringVar(&secretFile, "secret-file", os.Getenv("CLASH_OVERRIDE_SECRET_FILE"), "read the override secret for RESTful API from a file")
	flag.StringVar(&postUp, "post-up", os.Getenv("CLASH_POST_UP"), "set post-up script")
	flag.StringVar(&postDown, "post-down", os.Getenv("CLASH_POST_DOWN"), "set post-down script")
	flag.BoolVar(&geodataMode, "m", false, "set geodata mode")
	flag.BoolVar(&version, "v", false, "show current version of citrus")
	flag.BoolVar(&testConfig, "t", false, "test configuration and exit")
	flag.Parse()
}

func main() {
	// Defensive programming: panic when code mistakenly calls net.DefaultResolver
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		//panic("should never be called")
		buf := make([]byte, 1024)
		for {
			n := runtime.Stack(buf, true)
			if n < len(buf) {
				buf = buf[:n]
				break
			}
			buf = make([]byte, 2*len(buf))
		}
		fmt.Fprintf(os.Stderr, "panic: should never be called\n\n%s", buf) // always print all goroutine stack
		os.Exit(2)
		return nil, nil
	}

	_, _ = maxprocs.Set(maxprocs.Logger(func(string, ...any) {}))

	if len(os.Args) > 1 && os.Args[1] == "convert-ruleset" {
		provider.ConvertMain(os.Args[2:])
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "generate" {
		generator.Main(os.Args[2:])
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "age" {
		age.Main(os.Args[2:])
		return
	}

	if version {
		fmt.Printf("Citrus %s %s %s with %s %s\n",
			C.Version, runtime.GOOS, runtime.GOARCH, runtime.Version(), C.BuildTime)
		if tags := features.Tags(); len(tags) != 0 {
			fmt.Printf("Use tags: %s\n", strings.Join(tags, ", "))
		}

		return
	}

	if homeDir != "" {
		if !filepath.IsAbs(homeDir) {
			currentDir, _ := os.Getwd()
			homeDir = filepath.Join(currentDir, homeDir)
		}
		C.SetHomeDir(homeDir)
	}

	if geodataMode {
		geodata.SetGeodataMode(true)
	}

	// The file forms keep the secrets out of the process arguments, which other
	// users of the host may read.
	if ageSecretKeyFile != "" {
		if ageSecretKey != "" {
			log.Fatalln("Set -age-secret-key or -age-secret-key-file, not both")
		}
		data, err := os.ReadFile(ageSecretKeyFile)
		if err != nil {
			log.Fatalln("Read age-secret-key-file error: %s", err.Error())
		}
		ageSecretKey = strings.TrimSpace(string(data))
	}
	if secretFile != "" {
		if secret != "" {
			log.Fatalln("Set -secret or -secret-file, not both")
		}
		data, err := os.ReadFile(secretFile)
		if err != nil {
			log.Fatalln("Read secret-file error: %s", err.Error())
		}
		if secret = strings.TrimSpace(string(data)); secret == "" {
			log.Fatalln("secret-file %s is empty", secretFile)
		}
	}

	if ageSecretKey != "" {
		if err := age.VeritySecretKeys(ageSecretKey); err != nil {
			log.Errorln("Parse age-secret-key error: %s", err.Error())
		}
		age.SetGlobalSecretKeys(ageSecretKey)
	}

	if configString != "" {
		var err error
		configBytes, err = base64.StdEncoding.DecodeString(configString)
		if err != nil {
			log.Fatalln("Initial configuration error: %s", err.Error())
			return
		}
	} else if configFile == "-" {
		var err error
		configBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalln("Initial configuration error: %s", err.Error())
			return
		}
	} else {
		if configFile != "" {
			if !filepath.IsAbs(configFile) {
				currentDir, _ := os.Getwd()
				configFile = filepath.Join(currentDir, configFile)
			}
		} else {
			configFile = filepath.Join(C.Path.HomeDir(), C.Path.Config())
		}
		C.SetConfig(configFile)

		if err := config.Init(C.Path.HomeDir()); err != nil {
			log.Fatalln("Initial configuration directory error: %s", err.Error())
		}
	}

	if testConfig {
		if len(configBytes) != 0 {
			if _, err := executor.ParseWithBytes(configBytes); err != nil {
				log.Errorln("%s", err.Error())
				fmt.Println("configuration test failed")
				os.Exit(1)
			}
		} else {
			if _, err := executor.Parse(); err != nil {
				log.Errorln("%s", err.Error())
				fmt.Printf("configuration file %s test failed\n", C.Path.Config())
				os.Exit(1)
			}
		}
		fmt.Printf("configuration file %s test is successful\n", C.Path.Config())
		return
	}

	if runtime.GOOS == "windows" && features.AffectedByGoIssue78041(runtime.Version()) {
		log.Warnln("Built with %s, which corrupts memory on Windows when receiving UDP (https://go.dev/issue/78041) "+
			"and may crash at random; rebuild with go1.26.2 or newer", runtime.Version())
	}

	var options []hub.Option
	if externalUI != "" {
		if err := config.CheckExternalUI(externalUI, ""); err != nil {
			log.Fatalln("ext-ui error: %s", err.Error())
		}
		options = append(options, hub.WithExternalUI(externalUI))
	}
	if externalController != "" {
		options = append(options, hub.WithExternalController(externalController))
	}
	if externalControllerTLS != "" {
		options = append(options, hub.WithExternalControllerTLS(externalControllerTLS))
	}
	if externalControllerUnix != "" {
		options = append(options, hub.WithExternalControllerUnix(externalControllerUnix))
	}
	if externalControllerPipe != "" {
		options = append(options, hub.WithExternalControllerPipe(externalControllerPipe))
	}
	if externalControllerRoutingMark != 0 {
		options = append(options, hub.WithExternalControllerRoutingMark(externalControllerRoutingMark))
	}
	if externalControllerInsecure {
		options = append(options, hub.WithExternalControllerAllowInsecure(true))
	}
	if secret != "" {
		options = append(options, hub.WithSecret(secret))
	}

	if err := hub.Parse(configBytes, options...); err != nil {
		log.Fatalln("Parse config error: %s", err.Error())
	}

	if updater.GeoAutoUpdate() {
		updater.RegisterGeoUpdater()
	}

	if postDown != "" {
		defer func() {
			if _, err := cmd.ExecShell(postDown); err != nil {
				log.Errorln("post-down script error: %s", err.Error())
			}
		}()
	}
	if postUp != "" {
		if _, err := cmd.ExecShell(postUp); err != nil {
			log.Fatalln("post-up script error: %s", err.Error())
		}
	}

	defer executor.Shutdown()

	termSign := make(chan os.Signal, 1)
	hupSign := make(chan os.Signal, 1)
	signal.Notify(termSign, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(hupSign, syscall.SIGHUP)
	for {
		select {
		case <-termSign:
			return
		case <-hupSign:
			if err := hub.Parse(configBytes, options...); err != nil {
				log.Errorln("Parse config error: %s", err.Error())
			}
		}
	}
}
