// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @title ThreatReportRegistryV2
/// @notice Stores IPFS CIDs for threat reports on-chain and lets 3 reviewers
///         decide Verified/Rejected status by 2-of-3 voting.
/// @dev Report content (IP addresses, summaries, evidence) stays on IPFS.
///      Never store passwords, login attempts, personal evidence, or secrets here.
contract ThreatReportRegistryV2 {
    /// @notice The review state of a submitted report.
    enum ReviewStatus {
        Submitted,
        Verified,
        Rejected
    }

    /// @notice The only report details stored in contract storage.
    struct Report {
        string ipfsCid;
        address submitter;
        uint256 submittedAt;
        ReviewStatus status;
    }

    /// @notice A single reviewer's vote on a report.
    struct Vote {
        bool approve;
        bool cast;
    }

    /// @notice The 3 wallets allowed to vote on reports.
    address[3] public reviewers;

    /// @notice Number of reports submitted so far; also the next report ID.
    uint256 public reportCount;

    // Report IDs start at zero and increase by one for each submission.
    mapping(uint256 reportId => Report report) private reports;

    // reportId => reviewer => vote
    mapping(uint256 reportId => mapping(address reviewer => Vote vote)) private votes;

    // Tally of votes per report.
    mapping(uint256 reportId => uint256 approveCount) private approveCounts;
    mapping(uint256 reportId => uint256 rejectCount) private rejectCounts;

    /// @notice Emitted after a wallet submits an IPFS CID for a threat report.
    event ReportSubmitted(
        uint256 indexed reportId,
        string ipfsCid,
        address indexed submitter,
        uint256 submittedAt
    );

    /// @notice Emitted when a reviewer casts an approve/reject vote.
    event VoteCast(
        uint256 indexed reportId,
        address indexed reviewer,
        bool approve
    );

    /// @notice Emitted when a report reaches a final Verified/Rejected status.
    event ReportReviewed(
        uint256 indexed reportId,
        ReviewStatus status,
        uint256 approveCount,
        uint256 rejectCount
    );

    /// @notice Maximum allowed IPFS CID length in bytes.
    uint256 public constant MAX_CID_LENGTH = 128;

    error EmptyCid();
    error CidTooLong(uint256 length);
    error ReportNotFound(uint256 reportId);
    error NotReviewer();
    error AlreadyVoted(uint256 reportId);
    error AlreadyFinal(uint256 reportId);
    error SubmitterCannotVote(uint256 reportId);
    error DuplicateReviewer();
    error ZeroAddress();

    /// @notice Sets the 3 distinct reviewer wallets. The deployer is not a reviewer
    ///         unless explicitly included in the list.
    /// @param reviewerA First reviewer wallet.
    /// @param reviewerB Second reviewer wallet.
    /// @param reviewerC Third reviewer wallet.
    constructor(address reviewerA, address reviewerB, address reviewerC) {
        if (reviewerA == address(0) || reviewerB == address(0) || reviewerC == address(0)) {
            revert ZeroAddress();
        }
        if (reviewerA == reviewerB || reviewerA == reviewerC || reviewerB == reviewerC) {
            revert DuplicateReviewer();
        }

        reviewers[0] = reviewerA;
        reviewers[1] = reviewerB;
        reviewers[2] = reviewerC;
    }

    /// @dev Restricts a function to the 3 reviewer wallets.
    modifier onlyReviewer() {
        if (!isReviewer(msg.sender)) revert NotReviewer();
        _;
    }

    /// @notice Check whether a wallet is one of the 3 reviewers.
    /// @param account The wallet to check.
    /// @return True if the wallet is a reviewer.
    function isReviewer(address account) public view returns (bool) {
        return account == reviewers[0] || account == reviewers[1] || account == reviewers[2];
    }

    /// @notice Submit an IPFS CID for an off-chain threat report.
    /// @param ipfsCid The IPFS CID of the report content.
    /// @return reportId The numeric ID assigned to this report.
    function submitReport(string calldata ipfsCid) external returns (uint256 reportId) {
        uint256 cidLength = bytes(ipfsCid).length;
        if (cidLength == 0) revert EmptyCid();
        if (cidLength > MAX_CID_LENGTH) revert CidTooLong(cidLength);

        reportId = reportCount;
        reportCount += 1;

        reports[reportId] = Report({
            ipfsCid: ipfsCid,
            submitter: msg.sender,
            submittedAt: block.timestamp,
            status: ReviewStatus.Submitted
        });

        emit ReportSubmitted(reportId, ipfsCid, msg.sender, block.timestamp);
    }

    /// @notice Cast an approve or reject vote on a report. Each reviewer may vote
    ///         once per report, and only while the report is still Submitted.
    ///         2 approve votes set Verified; 2 reject votes set Rejected.
    /// @param reportId The numeric ID returned when the report was submitted.
    /// @param approve True to approve, false to reject.
    function vote(uint256 reportId, bool approve) external onlyReviewer {
        if (reportId >= reportCount) revert ReportNotFound(reportId);
        if (reports[reportId].status != ReviewStatus.Submitted) revert AlreadyFinal(reportId);
        if (reports[reportId].submitter == msg.sender) revert SubmitterCannotVote(reportId);
        if (votes[reportId][msg.sender].cast) revert AlreadyVoted(reportId);

        votes[reportId][msg.sender] = Vote({ approve: approve, cast: true });
        if (approve) {
            approveCounts[reportId] += 1;
        } else {
            rejectCounts[reportId] += 1;
        }

        emit VoteCast(reportId, msg.sender, approve);

        uint256 approves = approveCounts[reportId];
        uint256 rejects = rejectCounts[reportId];
        if (approves >= 2 || rejects >= 2) {
            ReviewStatus finalStatus = approves >= 2 ? ReviewStatus.Verified : ReviewStatus.Rejected;
            reports[reportId].status = finalStatus;
            emit ReportReviewed(reportId, finalStatus, approves, rejects);
        }
    }

    /// @notice Read a report using its numeric ID.
    /// @param reportId The numeric ID assigned at submission.
    /// @return report The CID, submitter, timestamp, and review status.
    function getReport(uint256 reportId) external view returns (Report memory report) {
        if (reportId >= reportCount) revert ReportNotFound(reportId);
        return reports[reportId];
    }

    /// @notice Read a reviewer's vote on a report.
    /// @param reportId The numeric ID assigned at submission.
    /// @param reviewer The reviewer wallet.
    /// @return voteRecord Whether the reviewer voted and whether they approved.
    function getVote(uint256 reportId, address reviewer) external view returns (Vote memory voteRecord) {
        if (reportId >= reportCount) revert ReportNotFound(reportId);
        return votes[reportId][reviewer];
    }

    /// @notice Read the approve/reject tally for a report.
    /// @param reportId The numeric ID assigned at submission.
    /// @return approves Number of approve votes cast.
    /// @return rejects Number of reject votes cast.
    function getVoteCounts(uint256 reportId) external view returns (uint256 approves, uint256 rejects) {
        if (reportId >= reportCount) revert ReportNotFound(reportId);
        return (approveCounts[reportId], rejectCounts[reportId]);
    }
}
