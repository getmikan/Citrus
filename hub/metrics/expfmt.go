package metrics

import (
	"bufio"
	"math"
	"strconv"
	"strings"
)

// A minimal writer of the Prometheus text exposition format (version 0.0.4),
// so that the core does not depend on the Prometheus client library.
//
// The format: every family starts with a # HELP and a # TYPE line, followed by
// all its samples; a sample is `name{label="value",...} value`. In HELP text a
// backslash and a line feed are escaped; in a label value a backslash, a double
// quote and a line feed are.

// ContentType is the media type of the text exposition format.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

type writer struct {
	w       *bufio.Writer
	scratch *[]byte
}

func newWriter(w *bufio.Writer) writer {
	b := make([]byte, 0, 32)
	return writer{w: w, scratch: &b}
}

var (
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
)

// family writes the HELP and TYPE lines of a metric family; typ is counter,
// gauge or histogram.
func (e writer) family(name, typ, help string) {
	e.w.WriteString("# HELP ")
	e.w.WriteString(name)
	e.w.WriteByte(' ')
	e.w.WriteString(helpEscaper.Replace(help))
	e.w.WriteString("\n# TYPE ")
	e.w.WriteString(name)
	e.w.WriteByte(' ')
	e.w.WriteString(typ)
	e.w.WriteByte('\n')
}

// sample writes a sample; labels are name, value pairs.
func (e writer) sample(name string, value []byte, labels ...string) {
	e.w.WriteString(name)
	if len(labels) > 0 {
		e.w.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				e.w.WriteByte(',')
			}
			e.w.WriteString(labels[i])
			e.w.WriteString(`="`)
			if v := labels[i+1]; strings.ContainsAny(v, "\\\"\n") {
				e.w.WriteString(labelEscaper.Replace(v))
			} else {
				e.w.WriteString(v)
			}
			e.w.WriteByte('"')
		}
		e.w.WriteByte('}')
	}
	e.w.WriteByte(' ')
	e.w.Write(value)
	e.w.WriteByte('\n')
}

func (e writer) int(name string, v int64, labels ...string) {
	*e.scratch = strconv.AppendInt((*e.scratch)[:0], v, 10)
	e.sample(name, *e.scratch, labels...)
}

func (e writer) float(name string, v float64, labels ...string) {
	*e.scratch = append((*e.scratch)[:0], formatFloat(v)...)
	e.sample(name, *e.scratch, labels...)
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func boolValue(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
