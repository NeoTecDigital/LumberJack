package replication

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func lockDirectory(dir string) (*os.File, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(dir, "raft.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func unlockDirectory(f *os.File) {
	if f == nil {
		return
	}
	unix.Flock(int(f.Fd()), unix.LOCK_UN)
	f.Close()
}
