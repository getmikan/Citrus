package log

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/observable"

	log "github.com/sirupsen/logrus"
)

var (
	logCh  = make(chan Event)
	source = observable.NewObservable[Event](logCh)
	level  = INFO
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(newFormatter(format, timestampFormat))
}

type Event struct {
	LogLevel LogLevel
	Payload  string
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

func Infoln(format string, v ...any) {
	if !Enabled(INFO) {
		return
	}
	event := newLog(INFO, format, v...)
	logCh <- event
	print(event)
}

func Warnln(format string, v ...any) {
	if !Enabled(WARNING) {
		return
	}
	event := newLog(WARNING, format, v...)
	logCh <- event
	print(event)
}

func Errorln(format string, v ...any) {
	if !Enabled(ERROR) {
		return
	}
	event := newLog(ERROR, format, v...)
	logCh <- event
	print(event)
}

func Debugln(format string, v ...any) {
	if !Enabled(DEBUG) {
		return
	}
	event := newLog(DEBUG, format, v...)
	logCh <- event
	print(event)
}

func Fatalln(format string, v ...any) {
	log.Fatalf(format, v...)
}

// subscriptions are the open Subscribe subscriptions (the /logs API). While
// there are none, a line below the level is neither formatted nor sent.
var (
	subMu         sync.Mutex
	subscriptions = map[observable.Subscription[Event]]struct{}{}
	subscribers   atomic.Int32
)

// Enabled reports whether a line of level l is printed or delivered to a
// subscriber. A caller that builds expensive arguments for a line can check
// it first.
func Enabled(l LogLevel) bool {
	return l >= level || subscribers.Load() > 0
}

func Subscribe() observable.Subscription[Event] {
	sub, err := source.Subscribe()
	if err == nil {
		subMu.Lock()
		subscriptions[sub] = struct{}{}
		subscribers.Store(int32(len(subscriptions)))
		subMu.Unlock()
	}
	return sub
}

func UnSubscribe(sub observable.Subscription[Event]) {
	subMu.Lock()
	delete(subscriptions, sub)
	subscribers.Store(int32(len(subscriptions)))
	subMu.Unlock()
	source.UnSubscribe(sub)
}

func Level() LogLevel {
	return level
}

func SetLevel(newLevel LogLevel) {
	level = newLevel
}

func print(data Event) {
	if data.LogLevel < level {
		return
	}

	switch data.LogLevel {
	case INFO:
		log.Infoln(data.Payload)
	case WARNING:
		log.Warnln(data.Payload)
	case ERROR:
		log.Errorln(data.Payload)
	case DEBUG:
		log.Debugln(data.Payload)
	}
}

func newLog(logLevel LogLevel, format string, v ...any) Event {
	return Event{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}
