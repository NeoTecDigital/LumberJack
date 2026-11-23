// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/internal/store"
	"github.com/NeoTecDigital/LumberJack/types"
)

type SealRequest struct {
	Directory string               `json:"directory"`
	Hub       string               `json:"hub_directory"`
	Name      string               `json:"name"`
	Principal string               `json:"principal"`
	Storage   *types.StorageConfig `json:"storage"`
}
type sealPhase func(string) error

func SealAccount(r SealRequest) (bool, error) {
	return sealAccount(r, func(string) error { return nil })
}
func component(s string) bool {
	return s != "" && len(s) <= 128 && s != "." && s != ".." && !strings.ContainsAny(s, "/\\*?[]\x00")
}
func (r SealRequest) validate() error {
	if !component(r.Name) || !component(r.Hub) || !store.ValidPrincipal(r.Principal) || !filepath.IsAbs(r.Directory) || r.Directory == "/" || filepath.Clean(r.Directory) != r.Directory {
		return store.ErrInvalid
	}
	cfg := r.Storage
	if cfg == nil || cfg.Mode == "" || cfg.MigrateLegacy || cfg.RewrapKeys || cfg.Validate() != nil {
		return types.ErrSealingLabel
	}
	if cfg.Mode == "local-test" {
		key, e := filepath.EvalSymlinks(cfg.LocalKeyFile)
		if e != nil {
			return types.ErrSealingLabel
		}
		key, e = filepath.Abs(key)
		if e != nil || key == r.Directory || strings.HasPrefix(key, r.Directory+string(filepath.Separator)) {
			return errors.New("wrapper must be outside account")
		}
	}
	real, e := filepath.EvalSymlinks(filepath.Join(r.Directory, r.Hub))
	if e != nil || real != filepath.Join(r.Directory, r.Hub) {
		return store.ErrInvalid
	}
	return nil
}
func existingLock(path string) (*os.File, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, store.ErrConflict
	}
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	if e = lockProfile(f, unclassifiedProfile); e != nil {
		f.Close()
		return nil, e
	}
	current, e := os.Lstat(path)
	if e != nil || !os.SameFile(info, current) {
		releaseLock(f)
		return nil, store.ErrConflict
	}
	return f, nil
}
func formatOf(path string) (bool, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() {
		return false, store.ErrConflict
	}
	f, e := os.Open(path)
	if e != nil {
		return false, e
	}
	defer f.Close()
	line, e := bufio.NewReader(io.LimitReader(f, 64)).ReadString('\n')
	if e != nil {
		return false, e
	}
	switch line {
	case "LUMBERJACK-RECORD-1\n":
		return false, nil
	case "LUMBERJACK-RECORD-2\n":
		return true, nil
	}
	return false, store.ErrConflict
}
func sealAccount(r SealRequest, at sealPhase) (bool, error) {
	if e := r.validate(); e != nil {
		return false, e
	}
	record := r.Name + ".dat"
	a, e := existingLock(filepath.Join(r.Directory, record+".lock"))
	if e != nil {
		return false, e
	}
	defer releaseLock(a)
	b, e := existingLock(filepath.Join(r.Directory, r.Hub, record+".lock"))
	if e != nil {
		return false, e
	}
	defer releaseLock(b)
	sealed, e := formatOf(filepath.Join(r.Directory, record))
	if e != nil {
		return false, e
	}
	return transactSeal(r, sealed, at)
}
func buildStage(r SealRequest, stage string, sealed bool, at sealPhase) error {
	record := r.Name + ".dat"
	var e error
	if e = os.Mkdir(stage, 0700); e != nil {
		return e
	}
	if e = copyAccount(r, stage); e != nil {
		return e
	}
	if e = at("copied"); e != nil {
		return e
	}
	if e = store.SealJournal(filepath.Join(stage, record), r.Principal, r.Storage, sealed); e != nil {
		return e
	}
	if e = at("records"); e != nil {
		return e
	}
	if e = internal.SealHubCopy(filepath.Join(stage, r.Hub), r.Name, *r.Storage, sealed); e != nil {
		return e
	}
	if e = at("verified"); e != nil {
		return e
	}
	return nil
}
func transactSeal(r SealRequest, sealed bool, at sealPhase) (already bool, result error) {
	record := r.Name + ".dat"
	var e error
	txn := r.Directory + ".seal-stage"
	stage := filepath.Join(txn, "candidate")
	if e = prepareStage(txn, r.Directory, record+".lock"); e != nil {
		return false, e
	}
	// After exchange stage names the old complete account. Do not remove it until the
	// parent directory sync succeeds: the filesystem may still roll the exchange back.
	cleanup := true
	defer func() {
		if cleanup {
			result = errors.Join(result, clearTransaction(txn))
		}
	}()
	if e = buildStage(r, stage, sealed, at); e != nil {
		return false, e
	}
	if sealed {
		return true, nil
	}
	if e = syncTree(stage); e != nil {
		return false, e
	}
	if e = syncParents(txn); e != nil {
		return false, e
	}
	if e = at("synced"); e != nil {
		return false, e
	}
	if e = exchangeDirs(r.Directory, stage); e != nil {
		return false, e
	}
	cleanup = false
	if e = at("exchanged"); e != nil {
		return false, e
	}
	if e = syncParents(txn); e != nil {
		return false, e
	}
	if e = at("published"); e != nil {
		return false, e
	}
	if e = clearTransaction(txn); e != nil {
		return false, e
	}
	return false, syncFile(filepath.Dir(txn))
}

// Recognize interrupted work only by the same locked sidecar inode, never its name alone.
func prepareStage(stage, source, lock string) error {
	info, e := os.Lstat(stage)
	if e == nil {
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			return store.ErrConflict
		}
		entries, e := os.ReadDir(stage)
		if e != nil {
			return e
		}
		if len(entries) > 0 {
			ours, e := os.Lstat(filepath.Join(stage, "guard"))
			if e != nil {
				return store.ErrConflict
			}
			held, e := os.Lstat(filepath.Join(source, lock))
			if e != nil || !os.SameFile(ours, held) {
				return store.ErrConflict
			}
		}
		if e = syncParents(stage); e != nil {
			return e
		}
		if e = clearTransaction(stage); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = os.Mkdir(stage, 0700); e != nil {
		return e
	}
	if e = os.Link(filepath.Join(source, lock), filepath.Join(stage, "guard")); e != nil {
		return e
	}
	return syncParents(stage)
}
func copyAccount(r SealRequest, stage string) error {
	recordLock := r.Name + ".dat.lock"
	return filepath.WalkDir(r.Directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(r.Directory, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(stage, rel)
		if d.IsDir() {
			if rel != r.Hub && rel != filepath.Join(r.Hub, r.Name+".objects") {
				return errors.New("unexpected directory in offline account")
			}
			return os.Mkdir(target, 0700)
		}
		if !d.Type().IsRegular() {
			return errors.New("special files not supported in offline account")
		}
		if rel == recordLock || rel == filepath.Join(r.Hub, recordLock) {
			return os.Link(path, target)
		}
		if filepath.Dir(rel) == "." && (strings.HasSuffix(rel, ".dat") && rel != r.Name+".dat" || strings.HasSuffix(rel, ".lock") || rel == types.StoreConfigFile) {
			return store.ErrConflict
		}
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Nlink != 1 {
			return errors.New("offline seal refuses linked account data")
		}
		if filepath.Dir(rel) == "." && strings.Contains(rel, ".dat.") && !strings.HasPrefix(rel, r.Name+".dat.log.") {
			return store.ErrConflict
		}
		return copyPrivate(path, target)
	})
}
func copyPrivate(src, dst string) error {
	f, e := os.Open(src)
	if e != nil {
		return e
	}
	defer f.Close()
	out, e := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, f)
	return errors.Join(e, out.Close())
}
func syncFile(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func syncTree(dir string) error {
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	for _, d := range entries {
		p := filepath.Join(dir, d.Name())
		if d.IsDir() {
			e = syncTree(p)
		} else {
			e = syncFile(p)
		}
		if e != nil {
			return fmt.Errorf("sync offline stage: %w", e)
		}
	}
	return syncFile(dir)
}

func syncParents(txn string) error {
	if e := syncFile(txn); e != nil {
		return e
	}
	return syncFile(filepath.Dir(txn))
}
func clearTransaction(txn string) error {
	entries, e := os.ReadDir(txn)
	if e != nil {
		return e
	}
	for _, f := range entries {
		if f.Name() != "candidate" && f.Name() != "guard" {
			return store.ErrConflict
		}
	}
	if e = os.RemoveAll(filepath.Join(txn, "candidate")); e != nil {
		return e
	}
	if e = syncFile(txn); e != nil {
		return e
	}
	if e = os.Remove(filepath.Join(txn, "guard")); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return os.Remove(txn)
}
