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

package server

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	customopts "github.com/containerd/containerd/v2/internal/cri/opts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupplementalGroupsCache(t *testing.T) {
	t.Run("copies cached values", func(t *testing.T) {
		cache := supplementalGroupsCache{}
		calls := 0
		source := []uint32{1, 2}
		key := customopts.SupplementalGroupsCacheKey{Snapshotter: "erofs", ChainID: "chain", User: "0"}
		resolver := func(context.Context) ([]uint32, error) {
			calls++
			return source, nil
		}

		first, err := cache.Resolve(context.Background(), key, resolver)
		require.NoError(t, err)
		source[1] = 88
		first[0] = 99

		second, err := cache.Resolve(context.Background(), key, resolver)
		require.NoError(t, err)
		assert.Equal(t, []uint32{1, 2}, second)
		assert.Equal(t, 1, calls)
	})

	t.Run("evicts least recently used entry", func(t *testing.T) {
		cache := supplementalGroupsCache{maxEntries: 2}
		for _, key := range []string{"one", "two"} {
			_, err := cache.Resolve(context.Background(), cacheKey(key), func(context.Context) ([]uint32, error) {
				return []uint32{1}, nil
			})
			require.NoError(t, err)
		}
		_, err := cache.Resolve(context.Background(), cacheKey("one"), func(context.Context) ([]uint32, error) {
			t.Fatal("recent entry should have been cached")
			return nil, nil
		})
		require.NoError(t, err)
		_, err = cache.Resolve(context.Background(), cacheKey("three"), func(context.Context) ([]uint32, error) {
			return []uint32{3}, nil
		})
		require.NoError(t, err)

		calls := 0
		_, err = cache.Resolve(context.Background(), cacheKey("two"), func(context.Context) ([]uint32, error) {
			calls++
			return []uint32{2}, nil
		})
		require.NoError(t, err)
		assert.Equal(t, 1, calls)
	})

	t.Run("coalesces concurrent misses", func(t *testing.T) {
		cache := supplementalGroupsCache{}
		var calls atomic.Int32
		started := make(chan struct{})
		release := make(chan struct{})
		resolver := func(context.Context) ([]uint32, error) {
			if calls.Add(1) == 1 {
				close(started)
			}
			<-release
			return []uint32{42}, nil
		}

		const workers = 8
		results := make(chan []uint32, workers)
		errs := make(chan error, workers)
		var wg sync.WaitGroup
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				gids, err := cache.Resolve(context.Background(), cacheKey("shared"), resolver)
				results <- gids
				errs <- err
			}()
		}
		<-started
		close(release)
		wg.Wait()
		close(results)
		close(errs)

		for err := range errs {
			require.NoError(t, err)
		}
		for gids := range results {
			assert.Equal(t, []uint32{42}, gids)
		}
		assert.EqualValues(t, 1, calls.Load())
	})

	t.Run("does not cache errors", func(t *testing.T) {
		cache := supplementalGroupsCache{}
		calls := 0
		resolver := func(context.Context) ([]uint32, error) {
			calls++
			if calls == 1 {
				return nil, assert.AnError
			}
			return []uint32{7}, nil
		}

		_, err := cache.Resolve(context.Background(), cacheKey("error"), resolver)
		require.ErrorIs(t, err, assert.AnError)
		gids, err := cache.Resolve(context.Background(), cacheKey("error"), resolver)
		require.NoError(t, err)
		assert.Equal(t, []uint32{7}, gids)
		assert.Equal(t, 2, calls)
	})

	t.Run("waiting caller can cancel", func(t *testing.T) {
		cache := supplementalGroupsCache{}
		started := make(chan struct{})
		release := make(chan struct{})
		firstDone := make(chan error, 1)
		go func() {
			_, err := cache.Resolve(context.Background(), cacheKey("cancel"), func(context.Context) ([]uint32, error) {
				close(started)
				<-release
				return []uint32{8}, nil
			})
			firstDone <- err
		}()
		<-started

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := cache.Resolve(ctx, cacheKey("cancel"), func(context.Context) ([]uint32, error) {
			t.Fatal("waiting caller must not run the resolver")
			return nil, nil
		})
		require.ErrorIs(t, err, context.Canceled)

		close(release)
		require.NoError(t, <-firstDone)
	})

	t.Run("healthy waiter retries canceled leader", func(t *testing.T) {
		cache := supplementalGroupsCache{}
		key := cacheKey("leader-cancel")
		leaderStarted := make(chan struct{})
		leaderCanReturn := make(chan struct{})
		var calls atomic.Int32
		resolver := func(ctx context.Context) ([]uint32, error) {
			if calls.Add(1) == 1 {
				close(leaderStarted)
				<-ctx.Done()
				<-leaderCanReturn
				return nil, ctx.Err()
			}
			return []uint32{9}, nil
		}

		leaderCtx, cancelLeader := context.WithCancel(context.Background())
		leaderDone := make(chan error, 1)
		go func() {
			_, err := cache.Resolve(leaderCtx, key, resolver)
			leaderDone <- err
		}()
		<-leaderStarted

		waiterDone := make(chan struct {
			gids []uint32
			err  error
		}, 1)
		go func() {
			gids, err := cache.Resolve(context.Background(), key, resolver)
			waiterDone <- struct {
				gids []uint32
				err  error
			}{gids: gids, err: err}
		}()

		cancelLeader()
		close(leaderCanReturn)
		require.ErrorIs(t, <-leaderDone, context.Canceled)

		result := <-waiterDone
		require.NoError(t, result.err)
		assert.Equal(t, []uint32{9}, result.gids)
		assert.EqualValues(t, 2, calls.Load())
	})
}

func cacheKey(chainID string) customopts.SupplementalGroupsCacheKey {
	return customopts.SupplementalGroupsCacheKey{
		Snapshotter: "erofs",
		ChainID:     chainID,
		User:        "0",
	}
}
