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

package snapshotters

import (
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

func TestDmveritySelectionsImageLabels(t *testing.T) {
	first := digest.FromString("first manifest")
	second := digest.FromString("second manifest")
	third := digest.FromString("third manifest")
	referrer := digest.FromString("signed first")
	another := digest.FromString("signed third")

	selections := &DmveritySelections{}
	selections.Record(first, referrer)
	selections.Record(second, "")
	labels := selections.ImageLabels(map[string]string{
		"user": "value",
		imageDmverityReferrerLabel + third.Encoded():  another.String(),
		imageDmverityReferrerLabel + second.Encoded(): digest.FromString("old second").String(),
	})
	require.Equal(t, "value", labels["user"])
	require.Equal(t, referrer.String(), labels[imageDmverityReferrerLabel+first.Encoded()])
	require.Equal(t, another.String(), labels[imageDmverityReferrerLabel+third.Encoded()])
	require.NotContains(t, labels, imageDmverityReferrerLabel+second.Encoded())
	require.Equal(t, "true", labels[imageDmverityNoReferrerLabel+second.Encoded()])

	selected, observed, err := imageDmveritySelection(labels, first)
	require.NoError(t, err)
	require.True(t, observed)
	require.Equal(t, referrer, selected)
	selected, observed, err = imageDmveritySelection(labels, second)
	require.NoError(t, err)
	require.True(t, observed)
	require.Empty(t, selected)
	_, observed, err = imageDmveritySelection(labels, digest.FromString("missing"))
	require.NoError(t, err)
	require.False(t, observed)

	selections.Record(second, referrer)
	rotated := selections.ImageLabels(labels)
	require.Equal(t, referrer.String(), rotated[imageDmverityReferrerLabel+second.Encoded()])
	require.NotContains(t, rotated, imageDmverityNoReferrerLabel+second.Encoded())

	rotated[imageDmverityNoReferrerLabel+second.Encoded()] = "true"
	_, _, err = imageDmveritySelection(rotated, second)
	require.ErrorContains(t, err, "conflicting")
	rotated[imageDmverityReferrerLabel+second.Encoded()] = "not-a-digest"
	delete(rotated, imageDmverityNoReferrerLabel+second.Encoded())
	_, _, err = imageDmveritySelection(rotated, second)
	require.ErrorContains(t, err, "invalid image dm-verity referrer")
}

func TestWithDmverityImageSelectionLabels(t *testing.T) {
	subject := digest.FromString("manifest")
	referrer := digest.FromString("referrer")
	signed := (&DmveritySelections{})
	signed.Record(subject, referrer)
	noReferrer := (&DmveritySelections{})
	noReferrer.Record(subject, "")

	labels := WithDmverityImageSelectionLabels(noReferrer.ImageLabels(map[string]string{
		"user": "value",
	}), signed.ImageLabels(nil))
	require.Equal(t, "value", labels["user"])
	require.Equal(t, signed.ImageLabels(nil), DmverityImageSelectionLabels(labels))

	labels = WithDmverityImageSelectionLabels(signed.ImageLabels(nil), noReferrer.ImageLabels(nil))
	require.Equal(t, noReferrer.ImageLabels(nil), DmverityImageSelectionLabels(labels))

	labels = WithDmverityImageSelectionLabels(nil, signed.ImageLabels(nil))
	require.Equal(t, signed.ImageLabels(nil), labels)
}

func TestDmveritySelectionFieldpaths(t *testing.T) {
	signed := digest.FromString("signed manifest")
	unsigned := digest.FromString("unsigned manifest")
	current := map[string]string{
		"io.cri-containerd.image":                         "managed",
		imageDmverityReferrerLabel + signed.Encoded():     digest.FromString("old referrer").String(),
		imageDmverityNoReferrerLabel + unsigned.Encoded(): "true",
	}
	desired := map[string]string{
		"io.cri-containerd.image":                       "managed",
		imageDmverityReferrerLabel + signed.Encoded():   digest.FromString("new referrer").String(),
		imageDmverityReferrerLabel + unsigned.Encoded(): digest.FromString("now signed").String(),
	}

	require.ElementsMatch(t, []string{
		"labels." + imageDmverityReferrerLabel + signed.Encoded(),
		"labels." + imageDmverityReferrerLabel + unsigned.Encoded(),
		"labels." + imageDmverityNoReferrerLabel + unsigned.Encoded(),
	}, DmveritySelectionFieldpaths(current, desired))
	require.Empty(t, DmveritySelectionFieldpaths(desired, desired))
}
