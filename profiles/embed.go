package profiles

import "embed"

// Files contains the authored profile sources and deterministic release inputs.
// Generated EPS files live beside their source so chart and runtime consumers
// read exactly what the compiler verified.
//
//go:embed strict/* standard/* open/*
var Files embed.FS
