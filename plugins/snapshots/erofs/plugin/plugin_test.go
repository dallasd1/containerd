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

package plugin

import (
	"errors"
	"testing"
)

func TestDmverityEnabled(t *testing.T) {
	probeError := errors.New("probe failed")
	tests := []struct {
		mode      string
		probeErr  error
		want      bool
		wantError bool
	}{
		{mode: "", want: true},
		{mode: "off"},
		{mode: "auto", want: true},
		{mode: "auto", probeErr: probeError},
		{mode: "on", want: true},
		{mode: "on", probeErr: probeError, wantError: true},
		{mode: "invalid"},
	}
	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			got, err := dmverityEnabled(test.mode, test.probeErr)
			if got != test.want {
				t.Fatalf("dmverityEnabled(%q) = %v, want %v", test.mode, got, test.want)
			}
			if (err != nil) != test.wantError {
				t.Fatalf("dmverityEnabled(%q) error = %v, wantError %v", test.mode, err, test.wantError)
			}
		})
	}
}
