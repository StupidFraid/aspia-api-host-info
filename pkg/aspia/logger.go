package aspia

import (
	"log"
)

var debugEnabled bool

// SetDebug enables or disables debug logging
func SetDebug(enabled bool) {
	debugEnabled = enabled
}

// DebugLog prints a log message only if debug is enabled
func DebugLog(format string, v ...interface{}) {
	if debugEnabled {
		log.Printf(format, v...)
	}
}
