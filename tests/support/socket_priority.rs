//! Keep exact TCP tuples ahead of wildcard listeners in the synthetic peer.
//!
//! smoltcp 0.14 dispatches to the first accepting socket. A recycled earlier
//! listener would otherwise claim a delayed SYN belonging to a later active
//! socket. Moving the existing sockets preserves their TCP state and every
//! queued packet; no traffic is filtered to work around the dispatch order.

use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::Socket,
};

pub fn prioritize_connections(
    sockets: &mut SocketSet<'_>,
) -> Option<Vec<(SocketHandle, SocketHandle)>> {
    let mut listener_seen = false;
    let unordered = sockets.iter().any(|(_, socket)| {
        let listening = matches!(socket, Socket::Tcp(tcp) if tcp.is_listening());
        let out_of_order = listener_seen && !listening;
        listener_seen |= listening;
        out_of_order
    });
    if !unordered {
        return None;
    }

    let mut order: Vec<_> = sockets
        .iter()
        .map(|(handle, socket)| {
            (
                handle,
                matches!(socket, Socket::Tcp(tcp) if tcp.is_listening()),
            )
        })
        .collect();
    order.sort_by_key(|(_, listening)| *listening);
    let mut reordered = SocketSet::new(Vec::new());
    let mapping = order
        .into_iter()
        .map(|(old, _)| (old, reordered.add(sockets.remove(old))))
        .collect();
    *sockets = reordered;
    Some(mapping)
}

pub fn remap(mapping: &[(SocketHandle, SocketHandle)], old: SocketHandle) -> SocketHandle {
    mapping
        .iter()
        .find_map(|&(previous, next)| (previous == old).then_some(next))
        .expect("every existing socket must retain a handle")
}
