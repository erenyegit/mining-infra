//! Block body validation at the ingress boundary (#130), and how copies of one
//! block race through it. Forwarding is observed through the sender's channel,
//! so "nothing was sent" is a direct check rather than a timeout. The races are
//! held open by state, a full send channel or a held permit, not by timing.
use super::nu7_fixture::{Nu7Fixture, tx_cache};
use super::*;
use crate::block::{compact_block_from_raw_block, reconstruct_block};
use sovright_relay::test_support::{committed_header, raw_block};
use sovright_relay::{
    BlockBodyError, RelayPayload, ZCASH_FULL_HEADER_SIZE, reassemble_raw_block,
    validate_block_body, validate_block_transactions, zcash_block_hash,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use zcash_pool_common::fixtures;

pub(crate) struct Harness {
    pub(crate) bridge: RelayBridge,
    pub(crate) outgoing: mpsc::Receiver<RelayPayload>,
    _client: RelayClient,
}

pub(crate) fn harness() -> Harness {
    let mut client = RelayClient::new(
        ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
            .with_auth_required(true),
    )
    .unwrap();
    let sender = client.sender();
    let (_receiver, outgoing) = client.take_receiver().unwrap();
    let bridge = RelayBridge {
        sender,
        data_shards: 10,
        parity_shards: 3,
        chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
        compact_from_tx_cache: false,
        skeleton_first: false,
        raw_fallback_with_tx_cache: false,
        raw_segment_send_rounds: 1,
        raw_segment_round_delay: Duration::ZERO,
        recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
            64,
            Duration::from_secs(30),
        ))),
        parse_permits: ParsePermits::new(),
        block_body_rejections: Default::default(),
    };
    Harness {
        bridge,
        outgoing,
        _client: client,
    }
}

impl Harness {
    pub(crate) fn sent(&mut self) -> Vec<RelayPayload> {
        let mut payloads = Vec::new();
        while let Ok(payload) = self.outgoing.try_recv() {
            payloads.push(payload);
        }
        payloads
    }

    fn recorded(&self, raw: &[u8]) -> bool {
        self.bridge.recent_forwarded.lock().unwrap().contains(
            &zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE]),
            std::time::Instant::now(),
        )
    }
}

/// The NU7 block with its v5 transaction changed: still parses, new txid.
pub(crate) fn good_and_bad() -> (Vec<u8>, Vec<u8>) {
    let fixture = Nu7Fixture::load();
    let tx = fixture.v5_transaction();
    let offset = fixture
        .raw
        .windows(tx.len())
        .position(|window| window == tx.as_slice())
        .unwrap();
    let mut bad = fixture.raw.clone();
    bad[offset + 169] ^= 0x01;
    (fixture.raw, bad)
}

fn block_from_compact(compact: &CompactBlock) -> Vec<u8> {
    let mut raw = compact.header.clone();
    crate::wire::encode_compact_size(compact.prefilled_txs.len() as u64, &mut raw);
    for tx in &compact.prefilled_txs {
        raw.extend_from_slice(&tx.tx_data);
    }
    raw
}

fn assert_rejected(result: Result<ForwardedBlock>, expected: BlockBodyError) {
    match result {
        Err(IngressError::InvalidBlockBody(error)) => assert_eq!(error, expected),
        Err(other) => panic!("expected {expected:?}, got {other}"),
        Ok(forwarded) => panic!(
            "expected {expected:?}, forwarded as {}",
            forwarded.mode.as_str()
        ),
    }
}

#[tokio::test]
async fn a_bad_body_is_neither_forwarded_nor_recorded() {
    let (_, bad) = good_and_bad();
    let mut harness = harness();

    assert_rejected(
        harness.bridge.forward_block(&bad, None).await,
        BlockBodyError::MerkleMismatch,
    );

    assert!(harness.sent().is_empty());
    assert!(!harness.recorded(&bad));
}

#[tokio::test]
async fn a_good_body_after_a_bad_one_is_forwarded_byte_for_byte() {
    let (good, bad) = good_and_bad();
    let mut harness = harness();
    assert!(harness.bridge.forward_block(&bad, None).await.is_err());

    let forwarded = harness.bridge.forward_block(&good, None).await.unwrap();

    assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
    assert!(harness.recorded(&good));
    let sent = harness.sent();
    let [RelayPayload::CompactBlock(compact)] = sent.as_slice() else {
        panic!("expected one compact block, got {sent:?}");
    };
    assert_eq!(block_from_compact(compact), good);
}

/// A known header is skipped before validation. Nothing is forwarded, so a bad
/// copy of a block already sent costs no hashing and changes nothing.
#[tokio::test]
async fn a_known_header_is_skipped_without_validation() {
    let (good, bad) = good_and_bad();
    let mut harness = harness();
    harness.bridge.forward_block(&good, None).await.unwrap();
    harness.sent();

    let repeat = harness.bridge.forward_block(&good, None).await.unwrap();
    let bad_copy = harness.bridge.forward_block(&bad, None).await.unwrap();

    assert_eq!(repeat.mode, ForwardMode::Deduplicated);
    assert_eq!(bad_copy.mode, ForwardMode::Deduplicated);
    assert!(harness.sent().is_empty());
}

#[tokio::test]
async fn a_large_block_is_forwarded_byte_for_byte_as_raw_segments() {
    let raw = fixtures::mainnet_raw_block();
    let mut harness = harness();

    let forwarded = harness.bridge.forward_block(&raw, None).await.unwrap();

    assert_eq!(forwarded.mode, ForwardMode::RawBlockSegments);
    let segments: Vec<RawBlockSegment> = harness
        .sent()
        .into_iter()
        .map(|payload| match payload {
            RelayPayload::RawBlockSegment(segment) => segment,
            other => panic!("expected a raw segment, got {other:?}"),
        })
        .collect();
    assert_eq!(reassemble_raw_block(&segments).unwrap(), raw);
}

/// Bytes that the block parser accepts but a strict reader must not.
#[tokio::test]
async fn parser_accepted_blocks_are_refused_before_sending() {
    let header = fixtures::mainnet_serialized_header();
    let txs = fixtures::mainnet_transactions();
    let with_count = |count: &[u8], txs: &[Vec<u8>]| {
        let mut raw = header.clone();
        raw.extend_from_slice(count);
        txs.iter().for_each(|tx| raw.extend_from_slice(tx));
        raw
    };
    let mut repeated = txs.clone();
    repeated.push(txs[6].clone());
    let cases = [
        (
            with_count(&[0xfd, 7, 0], &txs),
            BlockBodyError::InvalidCount,
        ),
        (
            with_count(&[8], &repeated),
            BlockBodyError::DuplicateTxid { index: 7 },
        ),
    ];
    for (raw, expected) in cases {
        let mut harness = harness();
        assert!(
            compact_block_from_raw_block(&raw).is_ok(),
            "parser accepts it"
        );
        assert_rejected(harness.bridge.forward_block(&raw, None).await, expected);
        assert!(harness.sent().is_empty());
        assert!(!harness.recorded(&raw));
    }
}

/// The block parser refuses these too, but the reader's reason is the one
/// reported. They must stay refused and send nothing.
#[tokio::test]
async fn malformed_blocks_send_nothing() {
    let raw = fixtures::mainnet_raw_block();
    let mut trailing = raw.clone();
    trailing.push(0);
    for malformed in [
        trailing,
        raw[..raw.len() - 1].to_vec(),
        raw[..raw.len() / 2].to_vec(),
    ] {
        let mut harness = harness();
        assert!(matches!(
            harness.bridge.forward_block(&malformed, None).await,
            Err(IngressError::InvalidBlockBody(_))
        ));
        assert!(harness.sent().is_empty());
        assert!(!harness.recorded(&malformed));
    }
}

/// The gateway still checks with the block parser and forwarding with the
/// transaction reader, so they must agree on real blocks.
#[test]
fn the_reader_and_the_block_parser_agree_on_real_blocks() {
    for raw in [Nu7Fixture::load().raw, fixtures::mainnet_raw_block()] {
        let compact = compact_block_from_raw_block(&raw).unwrap();
        assert_eq!(validate_block_body(&raw), Ok(compact.tx_count()));
    }
}

/// Peers and the gateway share one count, by the reason the reader gave, and a
/// refusal on length counts like any other. Only refusals count.
#[tokio::test]
async fn refused_bodies_are_counted_by_reason_on_both_entry_points() {
    let (good, bad) = good_and_bad();
    let oversized = vec![0; MAX_BLOCK_BYTES + 1];
    let harness = harness();
    let bridge = &harness.bridge;

    assert!(bridge.forward_block(&bad, None).await.is_err());
    assert!(bridge.forward_pool_block(&bad, None).await.is_err());
    assert!(bridge.forward_block(&oversized, None).await.is_err());
    assert!(bridge.forward_block(&[], None).await.is_err());
    bridge.forward_block(&good, None).await.unwrap();
    bridge.forward_block(&bad, None).await.unwrap();

    let count = |label| bridge.block_body_rejections.count(label);
    assert_eq!(count("merkle_mismatch"), 2, "a known header is not refused");
    assert_eq!(count("too_large"), 1);
    assert_eq!(count("invalid_header_length"), 1);
    assert_eq!(count("transaction"), 0);
}

/// A failed send says nothing about the body, so it is not a refusal.
#[tokio::test]
async fn a_relay_failure_is_not_counted_as_a_refused_body() {
    let (good, _) = good_and_bad();
    let Harness {
        bridge, outgoing, ..
    } = harness();
    drop(outgoing);

    let outcome = bridge.forward_block(&good, None).await;

    assert!(matches!(outcome, Err(IngressError::Relay(_))));
    for kind in BlockBodyError::ALL {
        let label = kind.label();
        assert_eq!(bridge.block_body_rejections.count(label), 0, "{label}");
    }
}

/// The dedup key is hashed from the header, so a payload that cannot hold one
/// stops here, with the same reason the reader gives.
#[tokio::test]
async fn a_payload_too_short_for_a_header_is_refused_before_dedup() {
    let raw = fixtures::mainnet_raw_block();
    for short in [&[][..], &raw[..ZCASH_FULL_HEADER_SIZE - 1]] {
        let mut harness = harness();
        assert_rejected(
            harness.bridge.forward_block(short, None).await,
            BlockBodyError::InvalidHeaderLength,
        );
        assert!(harness.sent().is_empty());
    }
}

/// A known header stops before any parsing, whatever follows it. The block
/// parser used to run first and refuse this one.
#[tokio::test]
async fn a_known_header_is_skipped_even_if_its_body_cannot_be_parsed() {
    let (good, _) = good_and_bad();
    let mut harness = harness();
    harness.bridge.forward_block(&good, None).await.unwrap();
    harness.sent();

    let truncated = harness
        .bridge
        .forward_block(&good[..good.len() - 1], None)
        .await
        .unwrap();
    let header_only = harness
        .bridge
        .forward_block(&good[..ZCASH_FULL_HEADER_SIZE], None)
        .await
        .unwrap();

    assert_eq!(truncated.mode, ForwardMode::Deduplicated);
    assert_eq!(header_only.mode, ForwardMode::Deduplicated);
    assert!(harness.sent().is_empty());
}

/// The delivery event keeps its transaction count without a parse.
#[tokio::test]
async fn a_deduplicated_delivery_reports_the_declared_count() {
    let raw = fixtures::mainnet_raw_block();
    let harness = harness();
    let first = harness.bridge.forward_block(&raw, None).await.unwrap();

    let repeat = harness.bridge.forward_block(&raw, None).await.unwrap();
    let header_only = harness
        .bridge
        .forward_block(&raw[..ZCASH_FULL_HEADER_SIZE], None)
        .await
        .unwrap();

    assert_eq!(repeat.mode, ForwardMode::Deduplicated);
    assert_eq!(repeat.tx_count, first.tx_count);
    assert_eq!(header_only.tx_count, 0);
}

/// What goes on the wire is what the reader validated, slice by slice.
#[tokio::test]
async fn the_forwarded_slices_are_the_readers_transactions() {
    let raw = Nu7Fixture::load().raw;
    let mut harness = harness();

    harness.bridge.forward_block(&raw, None).await.unwrap();

    let sent = harness.sent();
    let [RelayPayload::CompactBlock(compact)] = sent.as_slice() else {
        panic!("expected one compact block, got {sent:?}");
    };
    let slices: Vec<&[u8]> = compact
        .prefilled_txs
        .iter()
        .map(|tx| tx.tx_data.as_slice())
        .collect();
    let parsed = parse_block_body(raw).unwrap();
    assert_eq!(slices, parsed.transactions().collect::<Vec<_>>());
    assert_eq!(
        validate_block_transactions(&compact.header, slices.iter().copied()),
        Ok(2)
    );
}

/// A block of one empty transaction in the version 2 layout, with this header
/// word, and a header that commits to it.
fn block_with_transaction_header(transaction_header: u32) -> Vec<u8> {
    let mut tx = transaction_header.to_le_bytes().to_vec();
    tx.extend_from_slice(&[0, 0]); // no transparent inputs or outputs
    tx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
    tx.push(0); // no joinsplits
    let header = committed_header(0xab, std::slice::from_ref(&tx));
    raw_block(&header, std::slice::from_ref(&tx))
}

/// Parsing is not consensus, and this is where the two parsers differ on it.
/// With the overwinter flag clear, `zcash_primitives` reads every version from 3
/// up as version 2, the pre-Overwinter rule; the block parser stops at 2. So such
/// a block now goes out, where the block parser used to stop it.
///
/// That says the bytes are one transaction, not that a chain accepts it. Which
/// versions a height allows stays with the node, and nothing here adds that
/// rule. The pool gateway still checks with the block parser, so it still refuses
/// these. Real blocks read the same both ways, so only these show the block
/// parser is out of the forwarding path.
#[tokio::test]
async fn forwarding_follows_the_reader_which_does_not_judge_consensus() {
    for version in [3, 4, 5, 6, 0x7fff_ffff] {
        let raw = block_with_transaction_header(version);
        assert!(compact_block_from_raw_block(&raw).is_err());
        assert_eq!(validate_block_body(&raw), Ok(1), "version {version}");

        let mut harness = harness();
        let forwarded = harness.bridge.forward_block(&raw, None).await.unwrap();

        assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
        let sent = harness.sent();
        let [RelayPayload::CompactBlock(compact)] = sent.as_slice() else {
            panic!("expected one compact block, got {sent:?}");
        };
        assert_eq!(block_from_compact(compact), raw);
    }
}

/// The edges of that difference: version 2 reads the same both ways, and version
/// 0 and an overwintered header with no version group are refused by both.
#[tokio::test]
async fn the_parsers_agree_on_either_side_of_that_difference() {
    let agreed = block_with_transaction_header(2);
    assert!(compact_block_from_raw_block(&agreed).is_ok());
    assert_eq!(validate_block_body(&agreed), Ok(1));

    for transaction_header in [0, 0x8000_0003] {
        let raw = block_with_transaction_header(transaction_header);
        assert!(compact_block_from_raw_block(&raw).is_err());

        let mut harness = harness();
        assert_rejected(
            harness.bridge.forward_block(&raw, None).await,
            BlockBodyError::Transaction { index: 0 },
        );
        assert!(harness.sent().is_empty());
    }
}

/// Every object sent for a cached block: the skeleton, the full compact block
/// behind it, and the raw fallback. Each must give back the exact block.
#[tokio::test]
async fn every_object_sent_for_a_cached_block_carries_the_block() {
    let fixture = Nu7Fixture::load();
    let cache = tx_cache();
    cache.insert(fixture.v5_wtxid(), fixture.v5_transaction());
    let mut harness = harness();
    harness.bridge.compact_from_tx_cache = true;
    harness.bridge.skeleton_first = true;
    harness.bridge.raw_fallback_with_tx_cache = true;

    let forwarded = harness
        .bridge
        .forward_block(&fixture.raw, Some(&cache))
        .await
        .unwrap();

    assert_eq!(forwarded.mode, ForwardMode::CompactBlockWithRawFallback);
    let sent = harness.sent();
    let [
        RelayPayload::CompactSkeleton(skeleton),
        RelayPayload::CompactBlock(compact),
        fallback @ ..,
    ] = sent.as_slice()
    else {
        panic!("expected a skeleton and a compact block first, got {sent:?}");
    };
    assert_eq!(skeleton.short_ids.len(), 1);
    assert_eq!(compact.short_ids.len(), 1);
    assert_eq!(reconstruct_block(skeleton, &cache), fixture.raw);
    assert_eq!(reconstruct_block(compact, &cache), fixture.raw);
    let segments: Vec<RawBlockSegment> = fallback
        .iter()
        .map(|payload| match payload {
            RelayPayload::RawBlockSegment(segment) => segment.clone(),
            other => panic!("expected a raw segment, got {other:?}"),
        })
        .collect();
    assert_eq!(reassemble_raw_block(&segments).unwrap(), fixture.raw);
}

// ---------------------------------------------------------------------------
// Copies of one block racing through the forward path.
// ---------------------------------------------------------------------------

/// How many objects the relay client's send channel holds.
const OUTGOING_CAPACITY: usize = 16;

/// Only stops a hang. Nothing here asserts how long anything took.
async fn finishes<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .expect("did not finish")
}

pub(crate) async fn eventually(mut condition: impl FnMut() -> bool) {
    finishes(async {
        while !condition() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
}

pub(crate) fn hash_of(raw: &[u8]) -> [u8; 32] {
    zcash_block_hash(&raw[..ZCASH_FULL_HEADER_SIZE])
}

pub(crate) fn in_flight(bridge: &RelayBridge, hash: &[u8; 32]) -> bool {
    let recent = bridge.recent_forwarded.lock().unwrap();
    recent.in_flight.contains_key(hash)
}

/// How many copies are waiting on the send in progress.
fn waiting_on(bridge: &RelayBridge, hash: &[u8; 32]) -> usize {
    let recent = bridge.recent_forwarded.lock().unwrap();
    recent
        .in_flight
        .get(hash)
        .map_or(0, |sender| sender.receiver_count())
}

fn spawn_forward(bridge: &RelayBridge, raw: &[u8]) -> JoinHandle<Result<ForwardedBlock>> {
    let bridge = bridge.clone();
    let raw = raw.to_vec();
    tokio::spawn(async move { bridge.forward_block(&raw, None).await })
}

/// Leave the send channel full, so the next send waits until it is drained.
pub(crate) async fn fill_send_channel(bridge: &RelayBridge) {
    let filler = compact_block_from_raw_block(&block_with_transaction_header(2)).unwrap();
    for _ in 0..OUTGOING_CAPACITY {
        bridge.sender.send(filler.clone()).await.unwrap();
    }
}

async fn hold(permits: &Arc<Semaphore>) -> OwnedSemaphorePermit {
    Arc::clone(permits).acquire_owned().await.unwrap()
}

pub(crate) async fn hold_p2p_permit(bridge: &RelayBridge) -> OwnedSemaphorePermit {
    hold(&bridge.parse_permits.p2p).await
}

async fn spare_permit() -> OwnedSemaphorePermit {
    hold(&Arc::new(Semaphore::new(1))).await
}

async fn release_after_a_yield(permit: OwnedSemaphorePermit) {
    tokio::task::yield_now().await;
    drop(permit);
}

async fn cancel(task: JoinHandle<Result<ForwardedBlock>>) {
    task.abort();
    match task.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("the task finished before it was cancelled"),
    }
}

async fn forwarded(task: JoinHandle<Result<ForwardedBlock>>) -> ForwardedBlock {
    finishes(task).await.unwrap().unwrap()
}

pub(crate) fn compact_blocks_of(sent: &[RelayPayload], raw: &[u8]) -> usize {
    sent.iter()
        .filter(|payload| {
            matches!(payload, RelayPayload::CompactBlock(compact)
                if compact.header == raw[..ZCASH_FULL_HEADER_SIZE])
        })
        .count()
}

/// Two bodies for one header that both validate: a v6 txid leaves out the
/// scriptSig, so changing a byte of one keeps every txid and the merkle root.
fn two_valid_bodies() -> (Vec<u8>, Vec<u8>) {
    let header = fixtures::mainnet_serialized_header();
    let txs = fixtures::mainnet_transactions();
    let mut other = txs.clone();
    other[2][70] ^= 0x01;
    let (first, second) = (raw_block(&header, &txs), raw_block(&header, &other));
    assert_ne!(first, second);
    assert_eq!(validate_block_body(&second), Ok(txs.len()));
    (first, second)
}

/// Refused on length alone, so these neither queue for a permit nor get copied.
#[tokio::test]
async fn a_payload_of_the_wrong_length_needs_no_permit() {
    let harness = harness();
    let _p2p = hold(&harness.bridge.parse_permits.p2p).await;
    let _pool = hold(&harness.bridge.parse_permits.pool).await;
    let oversized = vec![0; MAX_BLOCK_BYTES + 1];
    let too_large = BlockBodyError::TooLarge {
        bytes: oversized.len(),
    };
    let short = &oversized[..ZCASH_FULL_HEADER_SIZE - 1];

    let bridge = &harness.bridge;
    assert_rejected(
        finishes(bridge.forward_block(&oversized, None)).await,
        too_large,
    );
    assert_rejected(
        finishes(bridge.forward_pool_block(&oversized, None)).await,
        too_large,
    );
    assert_rejected(
        finishes(bridge.forward_block(short, None)).await,
        BlockBodyError::InvalidHeaderLength,
    );
    assert_rejected(
        finishes(bridge.forward_pool_block(short, None)).await,
        BlockBodyError::InvalidHeaderLength,
    );
}

#[tokio::test]
async fn a_known_header_needs_no_permit() {
    let (good, _) = good_and_bad();
    let harness = harness();
    harness.bridge.forward_block(&good, None).await.unwrap();
    let _permit = hold(&harness.bridge.parse_permits.p2p).await;

    let repeat = finishes(harness.bridge.forward_block(&good, None))
        .await
        .unwrap();

    assert_eq!(repeat.mode, ForwardMode::Deduplicated);
}

#[tokio::test]
async fn the_gateway_and_the_peers_do_not_queue_behind_each_other() {
    let (good, _) = good_and_bad();
    let other = block_with_transaction_header(2);
    let harness = harness();

    let p2p = hold(&harness.bridge.parse_permits.p2p).await;
    let from_pool = finishes(harness.bridge.forward_pool_block(&good, None))
        .await
        .unwrap();
    drop(p2p);
    let _pool = hold(&harness.bridge.parse_permits.pool).await;
    assert_eq!(harness.bridge.parse_permits.pool.available_permits(), 0);
    let from_peer = finishes(harness.bridge.forward_block(&other, None))
        .await
        .unwrap();

    assert_eq!(from_pool.mode, ForwardMode::CompactBlock);
    assert_eq!(from_peer.mode, ForwardMode::CompactBlock);
}

/// They all queue on one permit, and only the first gets as far as sending.
#[tokio::test]
async fn concurrent_copies_of_a_block_are_sent_once() {
    let (good, _) = good_and_bad();
    let mut harness = harness();
    let permit = hold(&harness.bridge.parse_permits.p2p).await;
    assert_eq!(harness.bridge.parse_permits.p2p.available_permits(), 0);
    let copies: Vec<_> = (0..8)
        .map(|_| spawn_forward(&harness.bridge, &good))
        .collect();
    tokio::task::yield_now().await;
    assert!(harness.sent().is_empty(), "the permit holds them all back");
    assert!(copies.iter().all(|copy| !copy.is_finished()));

    drop(permit);

    let mut modes = Vec::new();
    for copy in copies {
        modes.push(forwarded(copy).await.mode);
    }
    let sends = modes
        .iter()
        .filter(|mode| **mode == ForwardMode::CompactBlock)
        .count();
    assert_eq!(sends, 1, "{modes:?}");
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
    assert!(!in_flight(&harness.bridge, &hash_of(&good)));
}

/// The bad copy goes first and fails its own parse. It holds no claim while it
/// does, so the good copy behind it is neither hidden nor deduplicated.
#[tokio::test]
async fn a_bad_copy_ahead_of_a_good_one_holds_nothing_back() {
    let (good, bad) = good_and_bad();
    let mut harness = harness();
    let permit = hold(&harness.bridge.parse_permits.p2p).await;

    let (bad_copy, good_copy, ()) = tokio::join!(
        harness.bridge.forward_block(&bad, None),
        harness.bridge.forward_block(&good, None),
        release_after_a_yield(permit),
    );

    assert_rejected(bad_copy, BlockBodyError::MerkleMismatch);
    assert_eq!(good_copy.unwrap().mode, ForwardMode::CompactBlock);
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
    assert!(harness.recorded(&good));
}

/// Behind a good copy, a bad one is settled by the recheck after its permit and
/// is never parsed: parsing it would have been refused, not deduplicated.
#[tokio::test]
async fn a_good_copy_ahead_of_a_bad_one_settles_it_unparsed() {
    let (good, bad) = good_and_bad();
    let mut harness = harness();
    let permit = hold(&harness.bridge.parse_permits.p2p).await;

    let (good_copy, bad_copy, ()) = tokio::join!(
        harness.bridge.forward_block(&good, None),
        harness.bridge.forward_block(&bad, None),
        release_after_a_yield(permit),
    );

    assert_eq!(good_copy.unwrap().mode, ForwardMode::CompactBlock);
    assert_eq!(bad_copy.unwrap().mode, ForwardMode::Deduplicated);
    let sent = harness.sent();
    let [RelayPayload::CompactBlock(compact)] = sent.as_slice() else {
        panic!("expected one compact block, got {sent:?}");
    };
    assert_eq!(block_from_compact(compact), good);
}

/// Nothing here can tell these two apart, so whichever validates first is sent.
/// That is the open limit on authorization-only changes, not a choice of body.
#[tokio::test]
async fn the_first_of_two_valid_bodies_is_the_one_sent() {
    let (first, second) = two_valid_bodies();
    let mut harness = harness();
    let permit = hold(&harness.bridge.parse_permits.p2p).await;

    let (first_copy, second_copy, ()) = tokio::join!(
        harness.bridge.forward_block(&first, None),
        harness.bridge.forward_block(&second, None),
        release_after_a_yield(permit),
    );

    assert_eq!(first_copy.unwrap().mode, ForwardMode::RawBlockSegments);
    assert_eq!(second_copy.unwrap().mode, ForwardMode::Deduplicated);
    let segments: Vec<RawBlockSegment> = harness
        .sent()
        .into_iter()
        .map(|payload| match payload {
            RelayPayload::RawBlockSegment(segment) => segment,
            other => panic!("expected a raw segment, got {other:?}"),
        })
        .collect();
    assert_eq!(reassemble_raw_block(&segments).unwrap(), first);
}

#[tokio::test]
async fn a_cancelled_send_passes_the_block_to_the_waiting_copy() {
    let (good, _) = good_and_bad();
    let hash = hash_of(&good);
    let mut harness = harness();
    fill_send_channel(&harness.bridge).await;
    let first = spawn_forward(&harness.bridge, &good);
    eventually(|| in_flight(&harness.bridge, &hash)).await;
    let second = spawn_forward(&harness.bridge, &good);
    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;

    cancel(first).await;

    eventually(|| in_flight(&harness.bridge, &hash)).await;
    assert_eq!(
        harness.sent().len(),
        OUTGOING_CAPACITY,
        "the cancelled send put nothing on the channel"
    );
    assert_eq!(forwarded(second).await.mode, ForwardMode::CompactBlock);
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
    assert!(harness.recorded(&good));
    assert!(!in_flight(&harness.bridge, &hash));
}

/// The two bridges share dedup state and permits, as clones do, but the first
/// sends through a channel that closes under it.
#[tokio::test]
async fn a_failed_send_passes_the_block_to_the_waiting_copy() {
    let (good, _) = good_and_bad();
    let hash = hash_of(&good);
    let mut harness = harness();
    let mut failing_client = RelayClient::new(
        ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
            .with_auth_required(true),
    )
    .unwrap();
    let (_receiver, failing_outgoing) = failing_client.take_receiver().unwrap();
    let mut failing = harness.bridge.clone();
    failing.sender = failing_client.sender();
    fill_send_channel(&failing).await;

    let first = spawn_forward(&failing, &good);
    eventually(|| in_flight(&harness.bridge, &hash)).await;
    let second = spawn_forward(&harness.bridge, &good);
    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;

    drop(failing_outgoing);

    assert!(matches!(
        finishes(first).await.unwrap(),
        Err(IngressError::Relay(_))
    ));
    assert_eq!(forwarded(second).await.mode, ForwardMode::CompactBlock);
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
    assert!(harness.recorded(&good));
    assert!(!in_flight(&harness.bridge, &hash));
}

/// With no channel left, every copy fails. None hangs and none is deduplicated
/// against a send that never finished.
#[tokio::test]
async fn a_closed_channel_fails_every_copy_and_records_nothing() {
    let (good, _) = good_and_bad();
    let hash = hash_of(&good);
    let Harness {
        bridge, outgoing, ..
    } = harness();
    fill_send_channel(&bridge).await;
    let first = spawn_forward(&bridge, &good);
    eventually(|| in_flight(&bridge, &hash)).await;
    let second = spawn_forward(&bridge, &good);
    eventually(|| waiting_on(&bridge, &hash) == 1).await;

    drop(outgoing);

    for copy in [first, second] {
        assert!(matches!(
            finishes(copy).await.unwrap(),
            Err(IngressError::Relay(_))
        ));
    }
    assert!(!in_flight(&bridge, &hash));
    assert!(matches!(bridge.forward_state(&hash), ForwardState::Open));
}

#[tokio::test]
async fn a_cancelled_waiter_leaves_the_send_alone() {
    let (good, _) = good_and_bad();
    let hash = hash_of(&good);
    let mut harness = harness();
    fill_send_channel(&harness.bridge).await;
    let first = spawn_forward(&harness.bridge, &good);
    eventually(|| in_flight(&harness.bridge, &hash)).await;
    let second = spawn_forward(&harness.bridge, &good);
    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;

    cancel(second).await;
    assert_eq!(waiting_on(&harness.bridge, &hash), 0);
    harness.sent();

    assert_eq!(forwarded(first).await.mode, ForwardMode::CompactBlock);
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
    assert!(harness.recorded(&good));
}

/// A copy still queueing for a permit has validated nothing, so it holds no
/// claim, and cancelling it leaves the block open for the next delivery.
#[tokio::test]
async fn a_copy_cancelled_in_the_queue_leaves_nothing_behind() {
    let (good, bad) = good_and_bad();
    let hash = hash_of(&good);
    let mut harness = harness();
    let permit = hold(&harness.bridge.parse_permits.p2p).await;
    let queued = spawn_forward(&harness.bridge, &bad);
    tokio::task::yield_now().await;
    assert!(!in_flight(&harness.bridge, &hash));

    cancel(queued).await;
    drop(permit);

    assert!(matches!(
        harness.bridge.forward_state(&hash),
        ForwardState::Open
    ));
    let forwarded = finishes(harness.bridge.forward_block(&good, None))
        .await
        .unwrap();
    assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
    assert_eq!(compact_blocks_of(&harness.sent(), &good), 1);
}

/// A copy that validated while another was claiming keeps what it prepared, and
/// sends it if the claim ends without a send.
#[tokio::test]
async fn a_dropped_claim_passes_to_a_copy_that_already_validated() {
    let hash = [0x51; 32];
    let harness = harness();
    let claim = harness
        .bridge
        .claim_forward(hash, spare_permit().await)
        .await
        .unwrap();
    let bridge = harness.bridge.clone();
    let permit = spare_permit().await;
    let waiter = tokio::spawn(async move { bridge.claim_forward(hash, permit).await.is_some() });
    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;

    drop(claim);

    assert!(finishes(waiter).await.unwrap());
    assert!(!in_flight(&harness.bridge, &hash));
}

#[tokio::test]
async fn a_committed_claim_settles_a_copy_that_already_validated() {
    let hash = [0x52; 32];
    let harness = harness();
    let claim = harness
        .bridge
        .claim_forward(hash, spare_permit().await)
        .await
        .unwrap();
    let bridge = harness.bridge.clone();
    let permit = spare_permit().await;
    let waiter = tokio::spawn(async move { bridge.claim_forward(hash, permit).await.is_some() });
    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;

    claim.commit();

    assert!(!finishes(waiter).await.unwrap());
    assert!(!in_flight(&harness.bridge, &hash));
    assert!(matches!(
        harness.bridge.forward_state(&hash),
        ForwardState::Forwarded
    ));
}

/// A copy that waits on someone else's send has finished its own work, so it
/// must not keep the next body in the queue from being parsed meanwhile.
#[tokio::test]
async fn a_copy_waiting_on_a_send_gives_its_permit_back() {
    let hash = [0x53; 32];
    let harness = harness();
    let claim = harness
        .bridge
        .claim_forward(hash, spare_permit().await)
        .await
        .unwrap();
    let permits = Arc::new(Semaphore::new(1));
    let permit = hold(&permits).await;
    let bridge = harness.bridge.clone();
    let waiter = tokio::spawn(async move { bridge.claim_forward(hash, permit).await.is_some() });

    eventually(|| waiting_on(&harness.bridge, &hash) == 1).await;
    assert_eq!(permits.available_permits(), 1);

    drop(claim);
    assert!(finishes(waiter).await.unwrap());
}

/// The work's permit comes back with its result, so a validated copy can keep it
/// until it has claimed the block. A copy that failed gives it up at once.
#[tokio::test]
async fn preparation_hands_the_permit_back_only_for_a_valid_body() {
    let (good, bad) = good_and_bad();
    let harness = harness();
    let permits = Arc::new(Semaphore::new(1));

    let prepared = harness
        .bridge
        .prepare_off_workers(&good, None, hold(&permits).await)
        .await
        .map(|(_, permit)| permit)
        .unwrap();
    assert_eq!(permits.available_permits(), 0);
    drop(prepared);

    let refused = harness
        .bridge
        .prepare_off_workers(&bad, None, hold(&permits).await)
        .await;
    assert!(matches!(refused, Err(IngressError::InvalidBlockBody(_))));
    assert_eq!(permits.available_permits(), 1);
}

/// Cancelling the caller does not stop blocking work, so the permit must stay
/// held until the work itself ends, or the limit counts only live callers.
#[tokio::test]
async fn a_cancelled_caller_leaves_the_permit_with_the_work() {
    let permits = Arc::new(Semaphore::new(1));
    let permit = hold(&permits).await;
    let (started, has_started) = std::sync::mpsc::channel();
    let (finish, may_finish) = std::sync::mpsc::channel::<()>();
    let caller = tokio::spawn(run_holding_permit(permit, move || {
        started.send(()).unwrap();
        may_finish.recv().unwrap();
    }));
    eventually(|| has_started.try_recv().is_ok()).await;

    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert_eq!(permits.available_permits(), 0);

    finish.send(()).unwrap();
    eventually(|| permits.available_permits() == 1).await;
}

#[tokio::test]
async fn a_panic_in_the_work_releases_the_permit() {
    let permits = Arc::new(Semaphore::new(1));
    let permit = hold(&permits).await;

    let result = finishes(run_holding_permit(permit, || -> () {
        panic!("the work failed")
    }))
    .await;

    assert!(result.unwrap_err().is_panic());
    assert_eq!(permits.available_permits(), 1);
}
