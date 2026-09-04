//go:build !linux

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
	"context"
	"fmt"
)

var errUnsupported = fmt.Errorf("dmverity is only supported on Linux systems")

// IsSupported reports whether the kernel can back a dm-verity device. On
// non-Linux platforms the answer is determinate, so this returns a nil error
// and lets callers skip cleanly rather than treating it as a failed check.
func IsSupported() (bool, error) {
	return false, nil
}

// CheckSignatureSupport reports that signed dm-verity mappings are
// unavailable on non-Linux platforms.
func CheckSignatureSupport() error {
	return errUnsupported
}

func Format(_ string, _ string, _ *DmverityOptions) (string, error) {
	return "", errUnsupported
}

func Open(_ string, _ string, _ string, _ string, _ uint64, _ *DmverityOptions) (string, error) {
	return "", errUnsupported
}

func OpenWithSignature(_ string, _ string, _ string, _ string, _ uint64, _ *DmverityOptions, _ string) (string, error) {
	return "", errUnsupported
}

func OpenWithSignatureData(_ string, _ string, _ string, _ string, _ uint64, _ *DmverityOptions, _ []byte) (string, error) {
	return "", errUnsupported
}

func VerifyArtifacts(_ string, _ string, _ string, _ uint32) error {
	return errUnsupported
}

func Close(_ string) error {
	return errUnsupported
}

func VerifySignedDevice(_ string, _ string) (DeviceInfo, error) {
	return DeviceInfo{}, errUnsupported
}

// FormatLayerBlob appends a dm-verity hash tree to an EROFS layer blob. It is
// only implemented on Linux; the stub keeps the package's exported surface
// identical on every platform, matching the other entry points here.
func FormatLayerBlob(_ context.Context, _ string, _ uint32, _ string) (string, error) {
	return "", errUnsupported
}
