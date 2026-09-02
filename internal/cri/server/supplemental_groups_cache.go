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
	"container/list"
	"context"
	"errors"
	"sync"

	customopts "github.com/containerd/containerd/v2/internal/cri/opts"
)

const defaultSupplementalGroupsCacheEntries = 1024

type supplementalGroupsCacheEntry struct {
	key  customopts.SupplementalGroupsCacheKey
	gids []uint32
}

type supplementalGroupsCacheCall struct {
	done  chan struct{}
	gids  []uint32
	err   error
	retry bool
}

type supplementalGroupsCache struct {
	mu         sync.Mutex
	entries    map[customopts.SupplementalGroupsCacheKey]*list.Element
	lru        list.List
	maxEntries int

	callMu sync.Mutex
	calls  map[customopts.SupplementalGroupsCacheKey]*supplementalGroupsCacheCall
}

func (c *supplementalGroupsCache) Resolve(
	ctx context.Context,
	key customopts.SupplementalGroupsCacheKey,
	resolver func(context.Context) ([]uint32, error),
) ([]uint32, error) {
	for {
		if gids, ok := c.get(key); ok {
			return gids, nil
		}

		c.callMu.Lock()
		if call, ok := c.calls[key]; ok {
			c.callMu.Unlock()
			select {
			case <-call.done:
				if call.retry && ctx.Err() == nil {
					continue
				}
				return cloneGIDs(call.gids), call.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if c.calls == nil {
			c.calls = make(map[customopts.SupplementalGroupsCacheKey]*supplementalGroupsCacheCall)
		}
		call := &supplementalGroupsCacheCall{done: make(chan struct{})}
		c.calls[key] = call
		c.callMu.Unlock()

		gids, ok := c.get(key)
		if !ok {
			gids, call.err = resolver(ctx)
			if call.err == nil {
				c.add(key, gids)
			} else if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(call.err, ctxErr) {
				call.retry = true
			}
		}

		c.callMu.Lock()
		call.gids = cloneGIDs(gids)
		delete(c.calls, key)
		close(call.done)
		c.callMu.Unlock()

		if call.err == nil {
			return cloneGIDs(gids), nil
		}
		return nil, call.err
	}
}

func (c *supplementalGroupsCache) get(key customopts.SupplementalGroupsCacheKey) ([]uint32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	element, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	c.lru.MoveToFront(element)
	entry := element.Value.(supplementalGroupsCacheEntry)
	return cloneGIDs(entry.gids), true
}

func (c *supplementalGroupsCache) add(key customopts.SupplementalGroupsCacheKey, gids []uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries == nil {
		c.entries = make(map[customopts.SupplementalGroupsCacheKey]*list.Element)
	}
	if element, ok := c.entries[key]; ok {
		element.Value = supplementalGroupsCacheEntry{key: key, gids: cloneGIDs(gids)}
		c.lru.MoveToFront(element)
		return
	}

	element := c.lru.PushFront(supplementalGroupsCacheEntry{
		key:  key,
		gids: cloneGIDs(gids),
	})
	c.entries[key] = element

	maxEntries := c.maxEntries
	if maxEntries <= 0 {
		maxEntries = defaultSupplementalGroupsCacheEntries
	}
	if c.lru.Len() <= maxEntries {
		return
	}
	oldest := c.lru.Back()
	delete(c.entries, oldest.Value.(supplementalGroupsCacheEntry).key)
	c.lru.Remove(oldest)
}

func cloneGIDs(gids []uint32) []uint32 {
	return append([]uint32(nil), gids...)
}
