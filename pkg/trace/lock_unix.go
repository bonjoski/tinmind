//go:build unix

package trace

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func verifyDirOwnership(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	euid := uint32(os.Geteuid())
	if st.Uid != euid && st.Uid != 0 {
		return fmt.Errorf("%w: directory %q owned by uid %d (expected %d)", ErrUnsafeTraceDir, path, st.Uid, euid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: directory %q is group/world writable (mode %04o)", ErrUnsafeTraceDir, path, fi.Mode().Perm())
	}
	return nil
}

// tryNonBlockingLock attempts an exclusive non-blocking flock on f.
// Returns (true, nil) if acquired, (false, nil) if already locked by another process.
func tryNonBlockingLock(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if err == unix.EWOULDBLOCK || err == unix.EAGAIN {
		return false, nil
	}
	return false, err
}

func unlockFile(f *os.File) {
	if f != nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	}
}
