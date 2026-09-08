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
		name      string
		required  bool
		probeErr  error
		want      bool
		wantError bool
	}{
		{name: "optional supported", want: true},
		{name: "optional probe failure", probeErr: probeError},
		{name: "required supported", required: true, want: true},
		{name: "required probe failure", required: true, probeErr: probeError, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := dmverityEnabled(test.required, test.probeErr)
			if got != test.want {
				t.Fatalf("dmverityEnabled() = %v, want %v", got, test.want)
			}
			if (err != nil) != test.wantError {
				t.Fatalf("dmverityEnabled() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}
