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

package local

import (
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
)

type dmverityReferrerMode uint8

const (
	dmverityReferrersDisabled dmverityReferrerMode = iota
	dmverityReferrersForImmediateUnpack
	dmverityReferrersRetained
)

func selectDmverityReferrerMode(enabled, unpackCapable bool) dmverityReferrerMode {
	if !enabled {
		return dmverityReferrersDisabled
	}
	if unpackCapable {
		return dmverityReferrersForImmediateUnpack
	}
	return dmverityReferrersRetained
}

func appendDmverityReferrerHandler(handler images.Handler, fetcher remotes.Fetcher, store content.Store, mode dmverityReferrerMode) images.Handler {
	switch mode {
	case dmverityReferrersForImmediateUnpack:
		return snpkg.AppendSignatureHandlerWrapper(fetcher)(handler)
	case dmverityReferrersRetained:
		return snpkg.AppendRetainedSignatureHandlerWrapper(fetcher, store)(handler)
	default:
		return handler
	}
}
