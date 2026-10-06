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
    /// arrival order. Under pressure it waits, and freed slots go to the
    /// waiting peers that have served this node the most verified content
    /// (`Tally.servingPriority`), oldest first among equals. False refuses
    /// the request: a duplicate, the peer's queue is full, or the global
    /// queue is full of requests from peers at least as helpful.
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
            guard let lowest = lowestPriorityWaitingTicket(),
                  tally.servingPriority(for: request.peer)
                    > tally.servingPriority(for: lowest.request.peer) else { return false }
            refuseServingTicket(lowest.request)
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

    /// Hands freed slots to waiting requests, most helpful peer first.
    func dispatchServingSlots() {
        guard hasFreeServingSlot, waitingServingTicketCount > 0 else { return }
        var priorities: [PeerID: Double] = [:]
        var active: [PeerID: Int] = [:]
        for request in servingContentRequests { active[request.peer, default: 0] += 1 }
        while hasFreeServingSlot,
              let next = bestEligibleWaitingTicket(active: active, priorities: &priorities) {
            servingContentRequests.insert(next.request)
            active[next.request.peer, default: 0] += 1
            resolveServingTicket(next.request, granted: true)
        }
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

    /// `active` counts each peer's slots; `priorities` caches one Tally read
    /// per peer for the duration of a dispatch.
    private func bestEligibleWaitingTicket(
        active: [PeerID: Int],
        priorities: inout [PeerID: Double]
    ) -> ServingTicket? {
        var best: (ticket: ServingTicket, priority: Double)?
        for ticket in servingTickets.values where ticket.state == .waiting
            && active[ticket.request.peer, default: 0]
                < config.maxConcurrentContentRequestsPerPeer {
            let peer = ticket.request.peer
            let priority = priorities[peer] ?? tally.servingPriority(for: peer)
            priorities[peer] = priority
            if let current = best,
               priority < current.priority
                || (priority == current.priority && ticket.arrival > current.ticket.arrival) {
                continue
            }
            best = (ticket, priority)
        }
        return best?.ticket
    }

    /// The waiting request to drop first: least helpful peer, newest among equals.
    private func lowestPriorityWaitingTicket() -> ServingTicket? {
        var lowest: (ticket: ServingTicket, priority: Double)?
        var priorities: [PeerID: Double] = [:]
        for ticket in servingTickets.values where ticket.state == .waiting {
            let peer = ticket.request.peer
            let priority = priorities[peer] ?? tally.servingPriority(for: peer)
            priorities[peer] = priority
            if let current = lowest,
               priority > current.priority
                || (priority == current.priority && ticket.arrival < current.ticket.arrival) {
                continue
            }
            lowest = (ticket, priority)
        }
        return lowest?.ticket
    }
}
