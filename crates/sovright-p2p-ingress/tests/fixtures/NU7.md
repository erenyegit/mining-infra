# NU7 activation fixture

`testnet_nu7_4465026.hex` is the unmodified public-testnet activation block.
Its metadata freezes the consensus block hash, raw-byte SHA-256, transaction
sizes, and `getblock` verbosity-2 txid/authdigest results from both pinned clients.
The raw block was also retrieved by public P2P `getdata`; its SHA-256 matches the
bytes accepted by Zebra in the earlier controlled activation replay. Public
fixture provenance contains no private host inventory or operational endpoints.

The block contains a v6 coinbase with one Ironwood action and a non-coinbase v5
transaction. Tests compare each transaction's digest against both node oracles
and reconstruct the exact raw bytes through all-prefilled, cached compact and
skeleton paths. Missing receiver cache data must first report incomplete.

The v6 coinbase remains prefilled: short-ID resolution here exercises only the
v5 transaction. Real non-coinbase v6 short-ID resolution is covered only with
pre-NU7 (NU6.3) mainnet transactions (`real_mainnet_block_round_trips_*` in
`src/block.rs`). This is not general shielded-transaction qualification. The two
clients share code ancestry; matching RPC digests are not independent
cryptographic implementations.

## Transport qualification

`real_nu7_authenticated_udp_reaches_sidecar_candidate` sends this fixture through
an authenticated loopback relay with production Equihash validation, 10+3 FEC,
and full-prefill compact reconstruction. It verifies byte-exact sidecar output
without submitting.

`real_nu7_cached_compact_and_skeleton_cross_authenticated_udp` sends the cached
compact block and the skeleton (its own relay object, v3 skeleton FEC profile)
for the same block. With the receiver's copy of the v5 transaction both
reconstruct the exact block; without it both prepare a getblocktxn request and
submit nothing. The sidecar only prepares that request on this path.

The ignored `live_nu7_authenticated_transport_submission` test requires explicit
`NU7_TEST_RAW_BLOCK` (hex file), `NU7_TEST_RAW_SHA256`, and `NU7_TEST_RPC_PORT`
(loopback RPC). It refuses any chain except `test` with active NU7, a known block,
or a block that does not extend the observed tip. Run only against an isolated
qualification node and a canonical block independently obtained from a reference
node. It performs one real submission and requires canonical acceptance; do not
retry an ambiguous RPC outcome without checking the node first.

```sh
cargo +1.99.0 test -p sovright-p2p-ingress --locked \
  live_nu7_authenticated_transport_submission -- --ignored --nocapture
```

## Content and loss (`src/nu7_relay_path_tests.rs`)

The sidecar verifies the merkle root only when short IDs are reconstructed.
All-prefilled compact blocks and raw segments are submitted without that check,
so these tests say nothing about them. Submissions go to a counting mock, not a
node.

- Short-ID path in live mode: the right transaction is submitted once with the
  fixture's bytes; a missing one prepares a request and submits nothing.
- Truncated, effecting-data-changed, v4 and NU6.3 v6 bytes cached under the v5
  transaction's wtxid fail the merkle check and are never submitted. They are
  rejected as different transactions, not by NU7 activation rules.
- Known gap: a v5 authorization-only change (scriptSig) keeps the txid
  (ZIP 244), passes the merkle check and is submitted. Block-commitment
  verification would be needed to catch it.
- 10+3 FEC on this block's compact payload, at the decoder: losing three data,
  mixed or parity shards recovers the exact block; losing parity as well, or
  four shards, does not decode.

Still open: network-level packet loss (the loopback relay has no point to
inject it), loss under the skeleton's v3 FEC profile, short-ID collision
detection in `prepare()`, sustained load, real node acceptance, and all testnet
difficulty targets.

These tests do not change the production testnet-output prohibition. The relay's
stateless target bound is the mainnet limit, not the larger testnet limit; full
nodes remain responsible for contextual difficulty and consensus validation.
