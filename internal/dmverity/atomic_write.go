/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package dmverity

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func writeFileAtomic(path string, data []byte, mode fs.FileMode) (retErr error) {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	closed := false
	defer func() {
		if !closed {
			if err := file.Close(); retErr == nil && err != nil {
				retErr = err
			}
		}
		if err := os.Remove(tempPath); retErr == nil && err != nil && !os.IsNotExist(err) {
			retErr = err
		}
	}()

	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary file mode: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	closed = true
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync directory %s: %w", dir, err)
	}
	return nil
}
