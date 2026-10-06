import Foundation
import Tally

/// A content request admitted to wait for a serving slot. It exists only
/// while slots are contended: with room, a request is served at once and
/// never becomes a ticket.
struct ServingTicket {
    enum State { case waiting, granted, refused }

    let request: InboundContentRequest
    let arrival: UInt64
    var state: State = .waiting
    /// Set once the request's task awaits the slot. A ticket can be granted
    /// or refused before that, and then answers immediately.
    var continuation: CheckedContinuation<Bool, Never>?
}

extension Ivy {
    /// Admits a request to be served, now or once a slot frees.
    ///
    /// With a free slot and nobody waiting, the request is served at once in
    /// arrival order. Under pressure it waits, and freed slots are shared
    /// among the waiting peers in proportion to their weight (see
    /// `servingWeight`): peers that served this node verified content get
    /// proportionally more, and a peer with no credit, such as a node syncing
    /// from scratch, always advances. Each peer queues within its own
    /// allotment (`maxQueuedContentRequestsPerPeer`), so no peer can crowd
    /// another out of the queue. False refuses a duplicate or a request over
    /// the peer's own allotment.
    ///
    /// Ivy treats CIDs as opaque, so it cannot tell verified content from
    /// bytes: the host credits a peer, through `tally.recordUsefulReceived`,
    /// when content it requested from that peer verifies. Without such
    /// credit every peer ranks equally and waiting is first come, first served.
    ///
    /// A Volume request's `requestTimeout` covers its time waiting, as the
    /// requester's does. Local reads (`localVolume`, local content) take any
    /// free slot without queueing: the node's own needs come first.
    func beginServingContent(_ request: InboundContentRequest) -> Bool {
        guard !servingContentRequests.contains(request),
              servingTickets[request] == nil else { return false }
        let peerActive = activeServingCount(of: request.peer)
        if waitingServingTicketCount == 0,
           hasFreeServingSlot,
           peerActive < config.maxConcurrentContentRequestsPerPeer {
            servingContentRequests.insert(request)
            return true
        }
        let peerWaiting = servingTickets.values.lazy
            .filter { $0.request.peer == request.peer && $0.state == .waiting }
            .count
        guard peerActive + peerWaiting
                < config.maxConcurrentContentRequestsPerPeer
                    + config.maxQueuedContentRequestsPerPeer else { return false }
        nextServingTicketArrival &+= 1
        servingTickets[request] = ServingTicket(request: request, arrival: nextServingTicketArrival)
        // Stride scheduling: a peer that starts waiting begins one stride
        // ahead of the virtual time and keeps its pass while it waits, so
        // re-joining cannot jump the peers already waiting.
        if peerWaiting == 0 {
            servingPass[request.peer] = servingVirtualTime + 1 / servingWeight(of: request.peer)
        }
        // The waiters ahead may all be peers at their own limit; a free slot
        // then goes to this request now rather than idling.
        dispatchServingSlots()
        return true
    }

    /// Waits until `request` holds a serving slot. True at once for a request
    /// admitted without waiting; false if it was refused or cancelled.
    func awaitServingSlot(_ request: InboundContentRequest) async -> Bool {
        if servingContentRequests.contains(request) { return true }
        guard let ticket = servingTickets[request] else { return false }
        switch ticket.state {
        case .granted:
            servingTickets.removeValue(forKey: request)
            return true
        case .refused:
            servingTickets.removeValue(forKey: request)
            return false
        case .waiting:
            break
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard !Task.isCancelled, var waiting = servingTickets[request],
                      waiting.state == .waiting else {
                    let granted = servingTickets.removeValue(forKey: request)?.state == .granted
                    continuation.resume(returning: granted && !Task.isCancelled)
                    return
                }
                waiting.continuation = continuation
                servingTickets[request] = waiting
            }
        } onCancel: {
            Task { await self.refuseServingTicket(request) }
        }
    }

    func endServingContent(_ request: InboundContentRequest) {
        servingContentTasks.removeValue(forKey: request)
        if let ticket = servingTickets.removeValue(forKey: request) {
            ticket.continuation?.resume(returning: false)
        }
        if servingContentRequests.remove(request) != nil {
            dispatchServingSlots()
        }
    }

    /// Hands freed slots to waiting requests by stride scheduling: the
    /// eligible peer with the lowest pass is served next (the older request
    /// among equals) and its pass advances by 1 / weight, so each waiting
    /// peer's share of slots is proportional to its weight. A peer that starts
    /// waiting begins one stride past the virtual time.
    func dispatchServingSlots() {
        guard hasFreeServingSlot, waitingServingTicketCount > 0 else { return }
        var active: [PeerID: Int] = [:]
        for request in servingContentRequests { active[request.peer, default: 0] += 1 }
        var weights: [PeerID: Double] = [:]
        while hasFreeServingSlot {
            var oldest: [PeerID: ServingTicket] = [:]
            for ticket in servingTickets.values where ticket.state == .waiting
                && active[ticket.request.peer, default: 0] < config.maxConcurrentContentRequestsPerPeer {
                let peer = ticket.request.peer
                if let current = oldest[peer], current.arrival < ticket.arrival { continue }
                oldest[peer] = ticket
            }
            var chosen: (ticket: ServingTicket, pass: Double, weight: Double)?
            for (peer, ticket) in oldest {
                let weight = weights[peer] ?? servingWeight(of: peer)
                weights[peer] = weight
                // A pass never counts below the virtual time: a peer skipped
                // while at its slot limit must not bank the delay.
                let pass = max(servingPass[peer] ?? servingVirtualTime + 1 / weight, servingVirtualTime)
                if let current = chosen,
                   pass > current.pass
                    || (pass == current.pass && ticket.arrival > current.ticket.arrival) {
                    continue
                }
                chosen = (ticket, pass, weight)
            }
            guard let next = chosen else { break }
            let peer = next.ticket.request.peer
            // Virtual time never moves backwards, or peers joining after it
            // would start below those already waiting.
            servingVirtualTime = max(servingVirtualTime, next.pass)
            servingPass[peer] = next.pass + 1 / next.weight
            servingContentRequests.insert(next.ticket.request)
            active[peer, default: 0] += 1
            resolveServingTicket(next.ticket.request, granted: true)
        }
        // Pass values matter only while a peer waits.
        let waiting = Set(servingTickets.values.lazy.filter { $0.state == .waiting }.map(\.request.peer))
        servingPass = servingPass.filter { waiting.contains($0.key) }
    }

    /// A peer's share of contended serving: 1 plus log2(1 + credit / 1 KiB),
    /// where credit is the verified content it served this node
    /// (`Tally.servingPriority`). Logarithmic, so credit multiplies a peer's
    /// share (1 MiB ≈ 11×, 1 GiB ≈ 21×) without reducing a peer with no
    /// credit to a negligible one.
    func servingWeight(of peer: PeerID) -> Double {
        1 + log2(1 + max(0, tally.servingPriority(for: peer)) / 1_024)
    }

    func refuseServingTicket(_ request: InboundContentRequest) {
        guard servingTickets[request]?.state == .waiting else { return }
        resolveServingTicket(request, granted: false)
    }

    /// Refuses every waiting request (on stop).
    func refuseAllServingTickets() {
        for request in Array(servingTickets.keys) { refuseServingTicket(request) }
    }

    private func resolveServingTicket(_ request: InboundContentRequest, granted: Bool) {
        guard var ticket = servingTickets[request] else { return }
        if let continuation = ticket.continuation {
            servingTickets.removeValue(forKey: request)
            continuation.resume(returning: granted)
        } else {
            ticket.state = granted ? .granted : .refused
            servingTickets[request] = ticket
        }
    }

    var hasFreeServingSlot: Bool {
        servingContentRequests.count + activeLocalContentRequestCount
            < config.maxConcurrentContentRequests
    }

    private var waitingServingTicketCount: Int {
        servingTickets.values.lazy.filter { $0.state == .waiting }.count
    }

    private func activeServingCount(of peer: PeerID) -> Int {
        servingContentRequests.lazy.filter { $0.peer == peer }.count
    }
}
