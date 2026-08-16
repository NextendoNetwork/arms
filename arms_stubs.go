package main

// ARMS-specific protocol handling — the analogue of splatoon-2/init_replay.go and
// super-smash-bros-ultimate/{init_replay,type8}.go.
//
// DataStore (0x73) is linked by the ARMS *update* only (the base game has no DataStore
// client at all) and nextendo-nex has no DataStore implementation, so this is a real gap.
// Both Splatoon 2 and SSBU needed a stub to get past online bring-up — SSBU soft-locks
// entering the online menu if these getters answer NotImplemented — so ARMS gets the same
// treatment. The stub is a GUESS at adequacy: it should carry ARMS through bring-up but will
// not support Party Crash / FestaRanking data. Every call is logged with protocol + method so
// a real implementation can be written from the first run's log.

import (
	"fmt"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

// protocolDataStore — nextendo-nex defines no constant for DataStore, so each game declares
// its own (splatoon-2/utility.go does the same; SSBU hardcodes the literal).
const protocolDataStore uint16 = 0x73

// resultDataStoreNotFound is DataStore::NotFound (facility 105). SSBU handles it gracefully
// where an empty success confuses it; assume the same for ARMS until observed otherwise.
const resultDataStoreNotFound uint32 = 0x80690004

// piaKeepalivePacketType is the undocumented PRUDP packet type 8 that Pia sends as a periodic
// keepalive on the secure stream (empty payload, NeedsAck, ~every 3s). The NEX SDK's own types
// stop at TYPE_RAW=7 and the base PRUDP switch only knows 0-4, so with no handler the
// keepalive went un-ACKed and SSBU treated the connection as dead → soft-lock entering the
// online menu. Whether ARMS's Pia 5.7.0 sends it is UNKNOWN; registering the handler is
// harmless for a title that never does.
const piaKeepalivePacketType uint8 = 8

// replayHandler answers every method of the given protocol with a minimal valid response —
// an empty list (count = 0), the benign "nothing here" answer for a getter. 0x73.8 is the one
// special case and returns DataStore::NotFound instead.
func replayHandler(proto uint16) nex.RMCHandler {
	return func(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		s := conn.Settings

		if proto == protocolDataStore && req.Method == 8 {
			fmt.Printf("[ARMS DataStore] 0x73.8 pid=%d callID=%d -> NotFound 0x%08x\n",
				conn.PID, req.CallID, resultDataStoreNotFound)
			return nex.NewRMCError(s, proto, req.CallID, resultDataStoreNotFound)
		}

		out := nex.NewStreamOut(s)
		out.U32(0) // empty list / count = 0
		fmt.Printf("[ARMS stub] proto=%#x method=%d call=%d pid=%d -> empty list (stub)\n",
			req.Protocol, req.Method, req.CallID, conn.PID)
		return nex.NewRMCSuccess(s, proto, req.Method, req.CallID, out.Bytes())
	}
}

// setupARMSStubs registers the DataStore (0x73) stub and the Pia type-8 keepalive ACK.
//
// Note that Endpoint.Register overwrites by protocol id. If ARMS turns out to need a stub for
// Utility (0x6E) rather than nextendo-nex's real handler — SSBU's situation — the one-line
// change is to call endpoint.Register(nex.ProtocolUtility, replayHandler(0x6E)) here, i.e.
// AFTER main.go's nex.UtilityHandler() registration.
func setupARMSStubs(endpoint *nex.Endpoint) {
	if envOr("ARMS_DATASTORE_STUB", "1") != "0" {
		endpoint.Register(protocolDataStore, replayHandler(protocolDataStore))
		fmt.Println("[ARMS Init] DataStore(0x73) stub registered (ARMS_DATASTORE_STUB=0 to disable)")
	} else {
		fmt.Println("[ARMS Init] DataStore(0x73) stub DISABLED — 0x73 will answer NotImplemented")
	}

	endpoint.RegisterCustomPacketHandler(piaKeepalivePacketType, func(c *nex.Connection, p *nex.Packet) {
		if p.HasFlag(nex.FlagNeedACK) {
			c.SendAck(p)
		}
		fmt.Printf("[ARMS Type8] Pia keepalive seqID=%d pid=%d -> ACK\n", p.PacketID, c.PID)
	})
}
