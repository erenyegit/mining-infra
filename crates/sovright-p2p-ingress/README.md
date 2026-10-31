# sovright-p2p-ingress

Native Zcash P2P ingress daemon for the Sovright relay network.

This is an MVP for timing and ingress experiments. It discovers Zcash mainnet
peers, performs the P2P handshake, listens for block inventory, requests block
payloads, and logs first-seen events. Optional crawler mode learns additional
peers from `addr` gossip and rotates through a bounded peer queue.

It does not consensus-validate blocks and does not submit blocks. Use Zebra as
the validation path.

## Run

```sh
RUST_LOG=info cargo run -p sovright-p2p-ingress
```

Useful environment variables:

```text
SOVRIGHT_P2P_DNS_SEEDS=dnsseed.z.cash,dnsseed.str4d.xyz,mainnet.seeder.zfnd.org,mainnet.is.yolo.money
SOVRIGHT_P2P_PEERS=1.2.3.4:8233
SOVRIGHT_P2P_MAX_PEERS=8
SOVRIGHT_P2P_CRAWLER_ENABLED=false
SOVRIGHT_P2P_CRAWLER_MAX_KNOWN_PEERS=5000
SOVRIGHT_P2P_CRAWLER_MAX_ADDR_PER_MESSAGE=1000
SOVRIGHT_P2P_CRAWLER_DRAIN_INTERVAL_SECS=5
SOVRIGHT_P2P_EVENT_LOG=/var/log/bedrock/zcash-p2p-ingress.jsonl
SOVRIGHT_P2P_RELAY_PEERS=10.40.0.3:8333
SOVRIGHT_P2P_RELAY_AUTH_KEY_HEX=<64 hex chars>
```

When crawler mode is enabled, the daemon still only makes outbound Zcash P2P
connections. It does not open an inbound listener, submit blocks, or forward to
FORGE unless the separate FORGE bridge settings are configured.

Measurement events include `p2p_connect_timing`, `p2p_handshake_timing`,
`p2p_ping_rtt`, `p2p_block_inv`, `p2p_getdata_sent`, and
`p2p_block_received`. These events are advisory telemetry only; crawler mode
does not rotate connections by score yet.

`p2p_block_received` is written as a block arrives, before it is parsed, and
counts deliveries. It no longer carries `miner_script` or `miner_tag`: those are on
a separate `p2p_block_coinbase` event with the same `hash`, `consensus_hash` and
`peer`, written once the coinbase has been read off the async workers. Join on
`hash`; do not count it as a delivery. With a relay bridge it appears once, for the
validated copy that was sent on, and not for a refused body or a repeat of a known
block. If the forward is cancelled or its send fails, the receipt stays and there
is no coinbase line. Without a bridge every delivery is read, so a block has one
line per delivery.

The FORGE bridge is disabled unless both `SOVRIGHT_P2P_RELAY_PEERS` and
`SOVRIGHT_P2P_RELAY_AUTH_KEY_HEX` are configured.
`SOVRIGHT_P2P_RELAY_DATA_SHARDS` and `SOVRIGHT_P2P_RELAY_PARITY_SHARDS`
override the default `10+3` FEC profile for relay traffic; they must match the
relay daemon and receiving sidecar.

## Refused block bodies

`forward_block` validates a block body before forwarding it. A refused body is
visible in two places:

- The Prometheus counter `sovright_p2p_ingress_block_body_rejected_total{reason}`
  counts refusals from P2P peers and the pool gateway. `reason` is one of
  `too_large`, `invalid_header_length`, `invalid_count`, `empty_transactions`,
  `transaction`, `transaction_boundary`, `trailing_bytes`, `duplicate_txid` and
  `merkle_mismatch`. It is the only label.
- The `p2p_block_body_rejected` JSON event identifies each refusal from a P2P
  peer, with `peer`, `hash`, `consensus_hash`, `reason`, `detail` and `bytes`.
  Pool gateway refusals are logged with their block hash instead.

The counter reaches Prometheus through a textfile, as the sidecar's do. Set
`SOVRIGHT_P2P_METRICS_TEXTFILE` to a `.prom` path that a textfile collector reads:

```text
SOVRIGHT_P2P_METRICS_TEXTFILE=/var/lib/sovright-p2p-ingress/metrics.prom
```

The file is rewritten every 30 seconds and starts at zero. It is written only
while the relay bridge is enabled, and testnet rejects the setting. Give each
process its own path: a collector refuses identical series from two files.

Nothing here is an alert. Monitoring needs the collector to read this path and a
rule of its own, for example:

```text
increase(sovright_p2p_ingress_block_body_rejected_total{reason="transaction"}[15m]) > 0
```

`transaction` and `trailing_bytes` can mean a valid block in a layout this reader
does not know, so they are the reasons to watch around a network upgrade. A
refused hash that later appears on chain is only a lead, because a bad body can
carry a real block's header. It was a false rejection only if the node accepted
those same bytes, and the event records their length, not a digest. Parsing is not
consensus validation: these checks do not decide which transaction versions a
height allows, and a block that passes them can still be invalid.

With `SOVRIGHT_P2P_PEER_SCORING_ENABLED`, a refused body costs the peer
`SOVRIGHT_P2P_PEER_SCORE_ERROR`, except for those two reasons. Only a block that is
validated and sent on earns the delivery rewards: a deduplicated copy earns and
costs nothing.

## Inventory limits

Inventory request bookkeeping is bounded per peer connection. These optional
environment variables control the limits:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SOVRIGHT_P2P_MAX_PENDING_BLOCKS` | `128` | Outstanding block requests per peer |
| `SOVRIGHT_P2P_MAX_PENDING_TXS` | `1024` | Outstanding transaction requests per peer |
| `SOVRIGHT_P2P_RECENT_INVENTORY_ENTRIES` | `4096` | Entries in each recent block-announcement, completed-block, and completed-transaction cache |
| `SOVRIGHT_P2P_REQUEST_TIMEOUT_SECS` | `30` | Response deadline, from 1 to 3600 seconds |

The existing `SOVRIGHT_P2P_TX_REQUEST_LIMIT_PER_INV` (default `256`) also limits
transaction requests from an individual inventory message. A zero pending limit
disables requests of that type; zero recent entries disables recent deduplication.
Outstanding requests remain deduplicated regardless of the recent-cache size.

When a request window is full, additional inventories are dropped without a retry
backlog. A later announcement may be requested after capacity becomes available.
Matching responses, `notfound`, expiry, and connection teardown free outstanding
request state. Expired and not-found items may be retried; completed items remain
deduplicated until evicted from the bounded recent cache. Duplicate announcements
do not extend response deadlines. Block announcement scoring remains independent
of request capacity. Transaction cache identities continue to come from received
payloads rather than request order.

### NU7 candidate compatibility

The mainnet ingress advertises protocol `170190` (ZIP 259). The transaction
parser is pinned to `zcash_primitives =0.31.0-pre.0` and
`zcash_protocol =0.11.0-pre.0`: the previous 0.10.x protocol dependency does not
recognize finalized NU7 branch ID `0x77190AD9`. Bumping only the advertised
version would leave NU7 transactions absent from the cache/compact path.

The NU7 parser regression fixtures establish structural decoding, not valid
proofs, signatures, or consensus acceptance. The v6 fixture changes a public
NU6.3 transaction's branch ID and therefore invalidates its original signatures;
the v5 fixture is an empty structural transaction. The historical v5/v6 digest
oracle tests remain in place. Eight additional transparent-only cases compare
v5/v6 txid and auth digests with a standalone Python implementation of ZIP 244
and ZIP 229. They cover NU7/NU6.3 branch separation, authorization-script changes,
and wire/display byte order. The generator uses only Python's standard library;
it does not derive expected values from the Rust parser. Reproduce the fixture:

```sh
python3 crates/sovright-p2p-ingress/tests/fixtures/generate_nu7_digests.py
cargo test -p sovright-p2p-ingress --locked nu7_transparent_digests_match_independent_reference
```

These synthetic spends have no real UTXO or valid signature and no shielded
bundles. Before deployment, qualify real NU7 transactions and blocks, shielded
digest agreement, full reconstruction/submission, and the exact prerelease
dependency build on testnet or an isolated network.

Set `SOVRIGHT_P2P_NETWORK=mainnet` (the default) or `testnet`. This selects
network magic, the default peer port (8233/18233), and advertised protocol
version (170190/170180). Unknown values fail startup. No arbitrary protocol
version override is supported.

Testnet is currently **observation-only**. It has no implicit DNS seeds; provide
explicit testnet peers or seeds. Relay peers, transaction-feed output, and the
submitblock RPC are rejected in testnet mode. Caches remain process-local and
all structured events carry `network`. Use a separate process and event-log
path, and keep that path out of mainnet collector inputs. Existing consumers
are not automatically made network-aware by the additional field.

```sh
SOVRIGHT_P2P_NETWORK=testnet \
SOVRIGHT_P2P_PEERS=127.0.0.1:18233 \
SOVRIGHT_P2P_EVENT_LOG=/tmp/sovright-testnet-observations.jsonl \
SOVRIGHT_P2P_PEER_RUNTIME_SECS=30 \
cargo run -p sovright-p2p-ingress --locked
```

Use an isolated testnet node for this example. A configured nonstandard port
still uses the selected network's magic; a wrong-network response fails framing.
Peer admission depends on the actual output path. A session with a relay bridge
or transaction feed requires the selected network's NU7 protocol floor from
startup. An observation-only session, with neither output, accepts `170120` and
newer. Testnet configuration currently prevents enabling either output.

The forwarding floor stays fixed before, during, and after activation, including
reorgs; neither peer-supplied height nor a calendar date can lower it. Existing
connections cannot renegotiate VERSION, and application messages are rejected
until VERSION admission and VERACK finish. Deploying this candidate restarts
connections under the new policy. This intentionally reduces the available
pre-activation peer pool; qualify peer diversity and freshness before rollout.
A claimed version is not proof of correct consensus behavior: full-node
validation and NU7 block/submission qualification remain required.
