//! Regression test for the health-probe session leak: a client that connects
//! and immediately disconnects (the kubelet `tcpSocket` probe pattern) must
//! make `verifier()` return an error promptly, leaving no live driver task.
//!
//! Before the fix this failed two ways:
//! - Racy wedge: when the driver observed EOF before the verifier's protocol
//!   request was registered, the request could never resolve and `verifier()`
//!   pended forever — pinning the session (and its MPC buffers) in any caller
//!   that awaits it without a timeout. Observed in prod as an unbounded RSS
//!   climb on idle notary pods.
//! - Detached driver: every `?` early return dropped the driver `JoinHandle`,
//!   which detaches the task instead of cancelling it.

use std::time::Duration;

/// Number of connect-then-disconnect cycles. The pre-fix wedge hits within a
/// handful of cycles, and each leaked driver task is one live task above
/// baseline, so both failure modes are unambiguous.
const CYCLES: usize = 50;

#[test]
fn aborted_connection_fails_fast_and_leaves_no_driver_task() {
    // A dedicated runtime whose only tasks are the ones this test spawns, so
    // `num_alive_tasks` counts leaked drivers and nothing else.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build runtime");

    runtime.block_on(async {
        for cycle in 0..CYCLES {
            let (client, server) = tokio::io::duplex(1 << 16);
            // The probe pattern: the client goes away before speaking the
            // protocol.
            drop(client);
            // Generous bound: on a dead socket the verifier fails in
            // microseconds unless it wedges, which is exactly the regression.
            tokio::time::timeout(Duration::from_secs(5), libid_tlsn::verifier(server))
                .await
                .unwrap_or_else(|_| {
                    panic!("cycle {cycle}: verifier wedged on a dead socket")
                })
                .err()
                .expect("verifier must fail on an immediately-closed socket");
        }

        // Give cancelled driver tasks time to finish unwinding before
        // counting what is left alive.
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    // Only the block_on future ran on this runtime, and it has completed, so
    // every task still alive is a leaked session driver.
    let alive = runtime.metrics().num_alive_tasks();
    assert_eq!(
        alive, 0,
        "{alive} driver task(s) leaked after {CYCLES} aborted connections"
    );
}
