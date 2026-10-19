pub mod batch;
pub mod fragmenter;
pub mod reassembler;
pub mod retry;
pub mod send;

pub use batch::{
    BURST_SLOT, SendFrame, batch_backend, batch_report, burst_msg_copy, recv_burst,
    recvmmsg_available, sendmmsg_available, with_burst_msg,
};
pub use batch::{LAST_HOP_DRAIN, record_drain_batch, record_extra_syscalls, record_send_group};

pub use fragmenter::DgramFragmenter;
pub(crate) use fragmenter::frag_id_reuse_blocked;
pub use reassembler::DgramReassembler;
pub(crate) use reassembler::Partial;
pub(crate) use reassembler::tombstone_bytes;
pub(crate) use retry::{
    UDP_RETRY_DEPTH, UDP_RETRY_INFLIGHT, UDP_RETRY_TIMEOUT, UdpRetry, retry_shards,
    spawn_retry_worker, udp_retry_submit, under_retry_deadline,
};
pub use retry::{UdpWriteDrop, udp_try_send, udp_try_send_grouped, udp_try_send_slice};
pub use send::{DatagramSend, PayloadSend, send_udp_batch, send_udp_datagram, try_send_datagram};
