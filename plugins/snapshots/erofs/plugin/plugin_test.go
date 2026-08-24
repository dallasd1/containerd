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

import "testing"

func TestDmverityReferrersEnabled(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{mode: "", want: false},
		{mode: "off", want: false},
		{mode: "auto", want: true},
		{mode: "on", want: true},
	}
	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			if got := dmverityReferrersEnabled(test.mode); got != test.want {
				t.Fatalf("dmverityReferrersEnabled(%q) = %v, want %v", test.mode, got, test.want)
			}
		})
	}
}
