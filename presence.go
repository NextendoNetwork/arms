// presence.go: the server knows who is online — every PID sending PRUDP packets is
// playing ARMS right now. Report active PIDs to nextendo-account every 30s so it keeps
// them ONLINE via its TTL and serves them back to the Switch's own friend list. Same
// mechanism Splatoon 2's proven server uses alongside the real nn::friends
// UpdateUserPresence path (citron forwards that one directly when the game calls it);
// this is the fallback presence source for the general "online" state.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	presenceInterval = 30 * time.Second
	presenceTTL      = 60 * time.Second
	presenceStatus   = 2 // "playing"
	armsAppID        = "01009b500007c000"
)

var (
	presMu   sync.Mutex
	presSeen = map[uint64]time.Time{}
)

func notePresenceSeen(pid uint64) {
	if pid == 0 {
		return
	}
	presMu.Lock()
	presSeen[pid] = time.Now()
	presMu.Unlock()
}

func activePIDs() []uint64 {
	now := time.Now()
	active := []uint64{}
	presMu.Lock()
	for pid, t := range presSeen {
		if now.Sub(t) < presenceTTL {
			active = append(active, pid)
		} else {
			delete(presSeen, pid)
		}
	}
	presMu.Unlock()
	return active
}

func startPresenceReporter() {
	base := envOr("NEXTENDO_ACCOUNT_URL", "http://nextendo-account:8080")
	internalKey := os.Getenv("NEXTENDO_INTERNAL_KEY")
	client := &http.Client{Timeout: 5 * time.Second}
	go func() {
		for {
			time.Sleep(presenceInterval)
			active := activePIDs()
			if len(active) == 0 {
				continue
			}
			body, err := json.Marshal(map[string]any{"appId": armsAppID, "status": presenceStatus, "pids": active})
			if err != nil {
				continue
			}
			req, err := http.NewRequest("POST", base+"/internal/presence-batch", bytes.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			// presence-batch is gated by internalOnly() on the account server; without this
			// header every report is rejected 401 and the client never sees it as an error
			// (a non-2xx response is not a Go `error`), so this silently did nothing before.
			req.Header.Set("X-Internal-Key", internalKey)
			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf("[ARMS Presence] batch report failed: %v\n", err)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				respBody, _ := io.ReadAll(resp.Body)
				fmt.Printf("[ARMS Presence] batch report rejected: HTTP %d: %s\n", resp.StatusCode, respBody)
			}
			resp.Body.Close()
		}
	}()
}
