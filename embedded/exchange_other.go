// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
//go:build !linux

package embedded

import "errors"

func exchangeDirs(a, b string) error {
	return errors.New("atomic directory exchange is not supported on this platform")
}
