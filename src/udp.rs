pub mod batch;
pub mod fragmenter;
pub mod reassembler;
pub mod retry;
pub mod send;

pub use batch::{
    batch_backend, batch_report, burst_msg_copy, recv_burst, recvmmsg_available,
    sendmmsg_available, BURST_SLOT,
};
pub use batch::{record_drain_batch, record_send_group, LAST_HOP_DRAIN};
pub use send::poll_once;

pub(crate) use fragmenter::frag_id_reuse_blocked;
pub use fragmenter::DgramFragmenter;
pub use reassembler::DgramReassembler;
pub(crate) use reassembler::Partial;
pub(crate) use retry::{
    retry_shards, spawn_retry_worker, udp_retry_submit, under_retry_deadline, UdpRetry,
    UDP_RETRY_DEPTH, UDP_RETRY_INFLIGHT, UDP_RETRY_TIMEOUT,
};
pub use retry::{udp_try_send, udp_try_send_grouped, udp_try_send_slice, UdpWriteDrop};
pub use send::{send_udp_datagram, try_send_datagram, DatagramSend, PayloadSend};
