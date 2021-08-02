package jwtmw

import "net/http"

type Level int

const (
	Debug Level = iota
	Info
)

// logger logs a message, compatible with log.Printf
type logger func(level Level, format string, args ...interface{})

// errorWriter writes an error into w
type errorWriter func(w http.ResponseWriter, r *http.Request, err error)
