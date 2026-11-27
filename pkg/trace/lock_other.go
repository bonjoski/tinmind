//go:build !unix

package trace

import "os"

func verifyDirOwnership(_ string, _ os.FileInfo) error {
	return nil
}

func tryNonBlockingLock(_ *os.File) (bool, error) {
	return true, nil
}

func unlockFile(_ *os.File) {}
