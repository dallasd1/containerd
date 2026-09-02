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
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/errdefs"

	"golang.org/x/sys/unix"
)

func TestRetainedDmverityDevicesLRU(t *testing.T) {
	cache := newRetainedDmverityDevices(2)
	cache.statSource = func(string) error { return nil }

	if evicted := cache.retain("a", "source-a"); len(evicted) != 0 {
		t.Fatalf("retain(a) evicted %v", evicted)
	}
	if evicted := cache.retain("b", "source-b"); len(evicted) != 0 {
		t.Fatalf("retain(b) evicted %v", evicted)
	}
	if !cache.take("a") {
		t.Fatal("take(a) did not find retained device")
	}
	if cache.take("a") {
		t.Fatal("take(a) found device twice")
	}
	if evicted := cache.retain("a", "source-a"); len(evicted) != 0 {
		t.Fatalf("retain(a) after take evicted %v", evicted)
	}

	if evicted := cache.retain("c", "source-c"); !slices.Equal(evicted, []string{"b"}) {
		t.Fatalf("retain(c) evicted %v, want [b]", evicted)
	}
	if cache.take("b") {
		t.Fatal("evicted device b remained in cache")
	}
	if !cache.take("a") || !cache.take("c") {
		t.Fatal("most recently used devices were not retained")
	}
}

func TestRetainedDmverityDevicesDisabled(t *testing.T) {
	cache := newRetainedDmverityDevices(0)
	listed := false
	cache.listDevices = func(string) ([]string, error) {
		listed = true
		return nil, nil
	}

	cache.prepare(context.Background(), "/root/snapshots/1/layer.erofs")
	if listed {
		t.Fatal("disabled cache enumerated device-mapper devices")
	}
	if cache.take("a") {
		t.Fatal("disabled cache retained a device")
	}
	if evicted := cache.retain("a", "source-a"); len(evicted) != 0 {
		t.Fatalf("disabled cache returned evictions: %v", evicted)
	}
}

func TestRetainedDmverityDevicesEvictsRemovedSources(t *testing.T) {
	cache := newRetainedDmverityDevices(3)
	removed := map[string]bool{}
	cache.statSource = func(source string) error {
		if removed[source] {
			return errors.New("removed")
		}
		return nil
	}

	cache.retain("a", "source-a")
	cache.retain("b", "source-b")
	removed["source-a"] = true

	if evicted := cache.retain("c", "source-c"); !slices.Equal(evicted, []string{"a"}) {
		t.Fatalf("retain(c) evicted %v, want removed device [a]", evicted)
	}
}

func TestRetainedDmverityDevicesTracksMountedSource(t *testing.T) {
	cache := newRetainedDmverityDevices(1)
	cache.statSource = func(string) error { return nil }

	cache.recordMount("a", "source-a")
	source, ok := cache.mountedSource("a")
	if !ok || source != "source-a" {
		t.Fatalf("mounted source = %q, %v", source, ok)
	}

	cache.retain("a", source)
	if _, ok := cache.mountedSource("a"); ok {
		t.Fatal("idle device remained in mounted-source tracking")
	}
	if !cache.contains("a") {
		t.Fatal("retained device is not discoverable by a concurrent final unmount")
	}
}

func TestOverlayMountDoesNotEnterDmverityCache(t *testing.T) {
	handler := newErofsMountHandler("", 2)
	listed := false
	handler.retainedDmverity.listDevices = func(string) ([]string, error) {
		listed = true
		return nil, nil
	}

	_, err := handler.Mount(context.Background(), mount.Mount{Type: "overlay"}, t.TempDir(), nil)
	if !errdefs.IsNotImplemented(err) {
		t.Fatalf("overlay mount returned %v, want not implemented", err)
	}
	if listed {
		t.Fatal("overlay mount entered dm-verity cache setup")
	}
}

func TestRetainedDmverityDevicesStartupCleanupRunsOnce(t *testing.T) {
	cache := newRetainedDmverityDevices(2)
	source := "/root/snapshots/1/layer.erofs"
	prefix := dmverity.ErofsDevicePrefix(source)
	cache.listDevices = func(gotPrefix string) ([]string, error) {
		if gotPrefix != prefix {
			t.Fatalf("list prefix = %q, want %q", gotPrefix, prefix)
		}
		return []string{prefix + "a", prefix + "b"}, nil
	}

	var closed []string
	cache.closeDevice = func(deviceName string) error {
		closed = append(closed, deviceName)
		if deviceName == prefix+"b" {
			return unix.EBUSY
		}
		return nil
	}

	cache.prepare(context.Background(), source)
	cache.prepare(context.Background(), source)

	if !slices.Equal(closed, []string{prefix + "a", prefix + "b"}) {
		t.Fatalf("startup cleanup closed %v", closed)
	}
}

func TestRetainedDmverityDevicesStartupCleanupRetriesListFailure(t *testing.T) {
	cache := newRetainedDmverityDevices(1)
	source := "/root/snapshots/1/layer.erofs"
	deviceName := dmverity.ErofsDeviceName(source)

	listCalls := 0
	cache.listDevices = func(string) ([]string, error) {
		listCalls++
		if listCalls == 1 {
			return nil, errors.New("temporary failure")
		}
		return []string{deviceName}, nil
	}
	closeCalls := 0
	cache.closeDevice = func(string) error {
		closeCalls++
		return nil
	}

	cache.prepare(context.Background(), source)
	cache.prepare(context.Background(), source)
	cache.prepare(context.Background(), source)

	if listCalls != 2 {
		t.Fatalf("list calls = %d, want 2", listCalls)
	}
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls)
	}
}

func TestLegacyDmverityDeviceName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		legacy bool
	}{
		{name: "containerd-erofs-42", legacy: true},
		{name: "containerd-erofs-deadbeefdeadbeef-42", legacy: false},
		{name: "unrelated-42", legacy: false},
	} {
		if got := isLegacyDmverityDeviceName(tc.name); got != tc.legacy {
			t.Errorf("isLegacyDmverityDeviceName(%q) = %v, want %v", tc.name, got, tc.legacy)
		}
	}
}
