import Testing
import Foundation
@testable import Tally

@Suite("Tally challenge API")
struct ChallengeAPITests {
    @Test("Challenges are peer-bound and Tally verification is single-use")
    func challengeHappyPathReplayAndBoundPeer() {
        let peer = PeerID(publicKey: "challenge-peer")
        let otherPeer = PeerID(publicKey: "challenge-other-peer")

        let challenge = Challenge(boundPeer: peer, difficulty: 8, expiresAfter: .seconds(30))
        let solver = ChallengeSolver()
        let solution = solver.solve(challenge)

        #expect(challenge.verify(solution: solution, peer: peer))
        #expect(!challenge.verify(solution: solution, peer: otherPeer))

        let tally = Tally(config: TallyConfig(challengeDifficulty: 8))
        let issued = tally.issueChallenge(for: peer)
        let issuedSolution = solver.solve(issued)

        #expect(!tally.verifyChallenge(issued, solution: issuedSolution, peer: otherPeer))
        #expect(tally.verifyChallenge(issued, solution: issuedSolution, peer: peer))
        #expect(!tally.verifyChallenge(issued, solution: issuedSolution, peer: peer))
    }
}
