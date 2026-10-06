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
    /// from scratch, always advances. False refuses the request: a duplicate,
    /// the peer's queue is full, or the global queue is full and this peer
    /// already has a request waiting and holds at least its weighted share.
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
        if waitingServingTicketCount >= config.maxQueuedContentRequests {
            // Make room by dropping the newest request of the peer holding
            // the most queue for its weight. A peer with nothing queued always
            // gets a place, so no peer - a syncing newcomer included - is
            // shut out of a full queue.
            guard let victim = mostOverQueuedTicket(),
                  peerWaiting == 0
                    || Double(peerWaiting + 1) / servingWeight(of: request.peer)
                        < victim.ratio else { return false }
            refuseServingTicket(victim.ticket.request)
        }
        nextServingTicketArrival &+= 1
        servingTickets[request] = ServingTicket(request: request, arrival: nextServingTicketArrival)
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
    /// eligible peer with the lowest pass is served next (higher weight, then
    /// older request, among equals) and its pass advances by 1 / weight, so
    /// each waiting peer's share of slots is proportional to its weight. A
    /// peer that starts waiting begins at the current virtual time.
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
                let pass = max(servingPass[peer] ?? servingVirtualTime, servingVirtualTime)
                if let current = chosen {
                    if pass > current.pass { continue }
                    if pass == current.pass {
                        if weight < current.weight { continue }
                        if weight == current.weight && ticket.arrival > current.ticket.arrival { continue }
                    }
                }
                chosen = (ticket, pass, weight)
            }
            guard let next = chosen else { break }
            let peer = next.ticket.request.peer
            servingVirtualTime = next.pass
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

    /// The newest waiting request of the peer holding the most queue for
    /// its weight, with that peer's waiting-count / weight.
    private func mostOverQueuedTicket() -> (ticket: ServingTicket, ratio: Double)? {
        var newest: [PeerID: ServingTicket] = [:]
        var counts: [PeerID: Int] = [:]
        for ticket in servingTickets.values where ticket.state == .waiting {
            let peer = ticket.request.peer
            counts[peer, default: 0] += 1
            if let current = newest[peer], current.arrival > ticket.arrival { continue }
            newest[peer] = ticket
        }
        var victim: (ticket: ServingTicket, ratio: Double)?
        for (peer, ticket) in newest {
            let ratio = Double(counts[peer] ?? 0) / servingWeight(of: peer)
            if let current = victim,
               ratio < current.ratio
                || (ratio == current.ratio && ticket.arrival < current.ticket.arrival) {
                continue
            }
            victim = (ticket, ratio)
        }
        return victim
    }
}
