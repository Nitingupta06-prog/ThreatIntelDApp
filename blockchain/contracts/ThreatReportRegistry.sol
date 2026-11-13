// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @title ThreatReportRegistry
/// @notice Stores report hashes and their audit status on-chain.
/// @dev Keep report text, IP addresses, and evidence off-chain. Submit only a hash.
contract ThreatReportRegistry {
    /// @notice The review state recorded for a submitted report.
    enum AuditStatus {
        Submitted,
        UnderReview,
        Verified,
        Rejected
    }

    /// @notice The only report details stored in contract storage.
    struct Report {
        bytes32 reportHash;
        uint256 submittedAt;
        address submitter;
        AuditStatus auditStatus;
    }

    /// @notice The wallet allowed to change audit statuses.
    address public admin;

    /// @notice Number of reports submitted so far; also the next report ID.
    uint256 public reportCount;

    // Report IDs start at zero and increase by one for each submission.
    mapping(uint256 reportId => Report report) private reports;

    /// @notice Emitted after a wallet submits a report hash.
    event ReportSubmitted(
        uint256 indexed reportId,
        bytes32 indexed reportHash,
        address indexed submitter,
        uint256 submittedAt
    );

    /// @notice Emitted whenever the admin changes a report's audit status.
    event AuditStatusUpdated(
        uint256 indexed reportId,
        AuditStatus previousStatus,
        AuditStatus newStatus,
        address indexed updatedBy
    );

    /// @notice Emitted when the admin wallet is transferred.
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    error ZeroReportHash();
    error ReportNotFound(uint256 reportId);
    error AdminOnly();
    error ZeroAddress();

    /// @notice The contract deployer becomes the admin.
    constructor() {
        admin = msg.sender;
    }

    /// @dev Restricts a function to the deployer/admin wallet.
    modifier onlyAdmin() {
        if (msg.sender != admin) revert AdminOnly();
        _;
    }

    /// @notice Submit a nonzero hash for an off-chain threat report.
    /// @param reportHash The hash of the report kept off-chain.
    /// @return reportId The numeric ID assigned to this report.
    function submitReport(bytes32 reportHash) external returns (uint256 reportId) {
        if (reportHash == bytes32(0)) revert ZeroReportHash();

        reportId = reportCount;
        reportCount += 1;

        reports[reportId] = Report({
            reportHash: reportHash,
            submittedAt: block.timestamp,
            submitter: msg.sender,
            auditStatus: AuditStatus.Submitted
        });

        emit ReportSubmitted(reportId, reportHash, msg.sender, block.timestamp);
    }

    /// @notice Transfer admin control to a new wallet. Only the current admin can call this.
    /// @param newAdmin The wallet that will become the admin.
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();

        address previousAdmin = admin;
        admin = newAdmin;

        emit AdminTransferred(previousAdmin, newAdmin);
    }

    /// @notice Change a report's audit status. Only the admin can call this.
    /// @param reportId The numeric ID returned when the report was submitted.
    /// @param newStatus The status to record for the report.
    function updateAuditStatus(uint256 reportId, AuditStatus newStatus) external onlyAdmin {
        if (reportId >= reportCount) revert ReportNotFound(reportId);

        AuditStatus previousStatus = reports[reportId].auditStatus;
        reports[reportId].auditStatus = newStatus;

        emit AuditStatusUpdated(reportId, previousStatus, newStatus, msg.sender);
    }

    /// @notice Read a report using its numeric ID.
    /// @param reportId The numeric ID assigned at submission.
    /// @return report The hash, timestamp, submitting wallet, and audit status.
    function getReport(uint256 reportId) external view returns (Report memory report) {
        if (reportId >= reportCount) revert ReportNotFound(reportId);
        return reports[reportId];
    }
}
