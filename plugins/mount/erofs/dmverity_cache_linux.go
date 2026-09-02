//go:build linux

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

package erofs

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/containerd/log"

	"github.com/containerd/containerd/v2/internal/dmverity"

	"golang.org/x/sys/unix"
)

type retainedDmverityDevice struct {
	name   string
	source string
}

// retainedDmverityDevices is a bounded cache of mapper names, not a source of
// trust. Mount removes a name before reuse and verifies the live mapper table
// against the signed root hash every time.
type retainedDmverityDevices struct {
	mu             sync.Mutex
	entries        map[string]*list.Element
	mountedSources map[string]string
	lru            list.List
	maxEntries     int

	prepareMu   sync.Mutex
	prepared    map[string]struct{}
	listDevices func(string) ([]string, error)
	closeDevice func(string) error
	statSource  func(string) error
}

func newRetainedDmverityDevices(maxEntries int) *retainedDmverityDevices {
	return &retainedDmverityDevices{
		maxEntries:  maxEntries,
		listDevices: listHostDmverityDevices,
		closeDevice: dmverity.Close,
		statSource: func(source string) error {
			_, err := os.Stat(source)
			return err
		},
	}
}

func (c *retainedDmverityDevices) enabled() bool {
	return c.maxEntries > 0
}

// prepare removes idle devices left by a previous containerd process. Busy
// devices remain valid and are verified by the normal mount path before reuse.
func (c *retainedDmverityDevices) prepare(ctx context.Context, source string) {
	if !c.enabled() {
		return
	}

	devicePrefix := dmverity.ErofsDevicePrefix(source)

	c.prepareMu.Lock()
	if _, ok := c.prepared[devicePrefix]; ok {
		c.prepareMu.Unlock()
		return
	}
	devices, err := c.listDevices(devicePrefix)
	if err != nil {
		c.prepareMu.Unlock()
		log.G(ctx).WithError(err).WithField("device-prefix", devicePrefix).Warn("failed to list retained dm-verity devices")
		return
	}
	if c.prepared == nil {
		c.prepared = make(map[string]struct{})
	}
	c.prepared[devicePrefix] = struct{}{}
	c.prepareMu.Unlock()

	c.close(context.WithoutCancel(ctx), devices, "startup cleanup")
}

// take removes a device from the idle LRU before a mount attempts to reuse it.
func (c *retainedDmverityDevices) take(deviceName string) bool {
	if !c.enabled() {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	element, ok := c.entries[deviceName]
	if !ok {
		return false
	}
	delete(c.entries, deviceName)
	c.lru.Remove(element)
	return true
}

func (c *retainedDmverityDevices) recordMount(deviceName, source string) {
	if !c.enabled() {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.mountedSources == nil {
		c.mountedSources = make(map[string]string)
	}
	c.mountedSources[deviceName] = source
}

func (c *retainedDmverityDevices) mountedSource(deviceName string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	source, ok := c.mountedSources[deviceName]
	return source, ok
}

func (c *retainedDmverityDevices) contains(deviceName string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[deviceName]
	return ok
}

// retain marks a successfully unmounted device as idle and returns devices
// that exceed the configured bound, from least to most recently used.
func (c *retainedDmverityDevices) retain(deviceName, source string) []string {
	if !c.enabled() {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries == nil {
		c.entries = make(map[string]*list.Element)
	}
	delete(c.mountedSources, deviceName)
	if element, ok := c.entries[deviceName]; ok {
		element.Value = retainedDmverityDevice{name: deviceName, source: source}
		c.lru.MoveToFront(element)
		return nil
	}

	c.entries[deviceName] = c.lru.PushFront(retainedDmverityDevice{
		name:   deviceName,
		source: source,
	})

	var evicted []string
	for name, element := range c.entries {
		entry := element.Value.(retainedDmverityDevice)
		if c.statSource(entry.source) == nil {
			continue
		}
		delete(c.entries, name)
		c.lru.Remove(element)
		evicted = append(evicted, name)
	}
	for c.lru.Len() > c.maxEntries {
		oldest := c.lru.Back()
		name := oldest.Value.(retainedDmverityDevice).name
		delete(c.entries, name)
		c.lru.Remove(oldest)
		evicted = append(evicted, name)
	}
	return evicted
}

func (c *retainedDmverityDevices) forgetMount(deviceName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.mountedSources, deviceName)
}

func (c *retainedDmverityDevices) close(ctx context.Context, deviceNames []string, reason string) {
	for _, deviceName := range deviceNames {
		unlock, err := dmverity.LockDevice(ctx, deviceName)
		if err != nil {
			log.G(ctx).WithError(err).WithField("device", deviceName).Warn("failed to lock dm-verity device for cleanup")
			continue
		}

		c.closeLocked(ctx, deviceName, reason)
		unlock()
	}
}

// closeLocked closes one device while its keyed lifecycle lock is held.
func (c *retainedDmverityDevices) closeLocked(ctx context.Context, deviceName, reason string) {
	err := c.closeDevice(deviceName)
	switch {
	case err == nil:
		log.G(ctx).WithFields(log.Fields{
			"device": deviceName,
			"reason": reason,
		}).Debug("dm-verity device closed")
	case errors.Is(err, unix.EBUSY):
		// A mounted filesystem owns the authoritative kernel reference. Its
		// final handler-driven unmount can retain the device again.
		log.G(ctx).WithFields(log.Fields{
			"device": deviceName,
			"reason": reason,
		}).Debug("dm-verity device is still active")
	case errors.Is(err, unix.ENXIO), errors.Is(err, os.ErrNotExist):
		// Another cleanup path won the race.
		log.G(ctx).WithFields(log.Fields{
			"device": deviceName,
			"reason": reason,
		}).Debug("dm-verity device is already absent")
	default:
		log.G(ctx).WithError(err).WithFields(log.Fields{
			"device": deviceName,
			"reason": reason,
		}).Warn("failed to close dm-verity device")
	}
}

func listHostDmverityDevices(devicePrefix string) ([]string, error) {
	deviceDir := filepath.Dir(dmverity.DevicePath("placeholder"))
	entries, err := os.ReadDir(deviceDir)
	if err != nil {
		return nil, fmt.Errorf("read device-mapper directory %q: %w", deviceDir, err)
	}

	devices := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), devicePrefix) || isLegacyDmverityDeviceName(entry.Name()) {
			devices = append(devices, entry.Name())
		}
	}
	return devices, nil
}

func isLegacyDmverityDeviceName(deviceName string) bool {
	snapshotID, ok := strings.CutPrefix(deviceName, dmverity.ErofsDeviceNamePrefix)
	if !ok {
		return false
	}
	_, err := strconv.ParseUint(snapshotID, 10, 64)
	return err == nil
}
