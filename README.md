<h1 align="center">arms</h1>

<p align="center">
  <b>Nextendo Network game server for ARMS.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-PolyForm%20Shield%201.0.0-orange" alt="License: PolyForm Shield 1.0.0">
  <img src="https://img.shields.io/badge/go-1.23%2B-00ADD8" alt="Go 1.23+">
</p>

---

## What is this?

The NEX game server for **ARMS** on [Nextendo Network](https://nextendo.network). It handles
authentication and matchmaking, speaking the same NEX protocol the retail servers did.

It is built on the [**nextendo-nex**](https://github.com/NextendoNetwork/nextendo-nex) core, which
provides the PRUDP transport, RMC layer, and common service protocols.

**Status:** verified against a real ARMS client on a VPS test rig — LoginEx, ticket
issuance, secure connect, and `autoMatchmake` gathering creation all succeed with the same setup as
the proven mk8/ssbu servers (access key `b6b34c51`, plain `prudp` scheme, default
`SecureConnectionHandler`)

**Not yet verified:** Friends List Lobby Joining/Hosting. Otherwise, standard Party Battle works.

## Running

```sh
cp example.env .env    # then edit .env
go run .
```

Configuration is entirely through environment variables — see [`example.env`](example.env). No
secrets are baked into the source: the auth/secure password, internal key, and token secret are all
read from the environment at startup.

## What this is not

This server ships **no** Nintendo code, keys, or copyrighted assets. It is an independent
reimplementation for use with a community-run replacement service, not affiliated with, endorsed by,
or associated with Nintendo. The NEX access key it uses is a well-known per-title value derivable
from the game itself, not a secret.

## License

Released under the **[PolyForm Shield License 1.0.0](LICENSE.md)** — source-available: read, use,
modify, and self-host, but do not use it to provide a product that competes with Nextendo Network.
