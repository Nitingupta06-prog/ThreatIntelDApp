import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

async function deployRegistry() {
  return ethers.deployContract("ThreatReportRegistry");
}

describe("ThreatReportRegistry", function () {
  it("lets a wallet submit a nonzero hash and stores the submitted report fields", async function () {
    const [, reporter] = await ethers.getSigners();
    const registry = await deployRegistry();
    const reportHash = ethers.id("synthetic off-chain threat report");

    const transaction = await registry.connect(reporter).submitReport(reportHash);
    const receipt = await transaction.wait();
    expect(receipt).not.to.be.null;

    const block = await ethers.provider.getBlock(receipt!.blockNumber);
    expect(block).not.to.be.null;

    const events = await registry.queryFilter(registry.filters.ReportSubmitted());
    expect(events).to.have.lengthOf(1);
    const event = events[0]!;
    expect(event.args.reportId).to.equal(0n);
    expect(event.args.reportHash).to.equal(reportHash);
    expect(event.args.submitter).to.equal(reporter.address);
    expect(event.args.submittedAt).to.equal(BigInt(block!.timestamp));

    const report = await registry.getReport(0);
    expect(report.reportHash).to.equal(reportHash);
    expect(report.submittedAt).to.equal(BigInt(block!.timestamp));
    expect(report.submitter).to.equal(reporter.address);
    expect(report.auditStatus).to.equal(0n); // Submitted
  });

  it("rejects a zero report hash", async function () {
    const registry = await deployRegistry();

    await expect(registry.submitReport(ethers.ZeroHash))
      .to.be.revertedWithCustomError(registry, "ZeroReportHash");
  });

  it("allows the deployer/admin to update status and emits the audit event", async function () {
    const [admin] = await ethers.getSigners();
    const registry = await deployRegistry();
    const reportHash = ethers.id("report awaiting review");
    await registry.submitReport(reportHash);

    await expect(registry.updateAuditStatus(0, 2)) // Verified
      .to.emit(registry, "AuditStatusUpdated")
      .withArgs(0n, 0n, 2n, admin.address);

    const report = await registry.getReport(0);
    expect(report.auditStatus).to.equal(2n); // Verified
  });

  it("rejects an audit-status update from a non-admin wallet", async function () {
    const [, nonAdmin] = await ethers.getSigners();
    const registry = await deployRegistry();
    await registry.submitReport(ethers.id("report awaiting review"));

    await expect(registry.connect(nonAdmin).updateAuditStatus(0, 2))
      .to.be.revertedWithCustomError(registry, "AdminOnly");
  });

  it("reverts when reading an unknown report ID", async function () {
    const registry = await deployRegistry();

    await expect(registry.getReport(0))
      .to.be.revertedWithCustomError(registry, "ReportNotFound")
      .withArgs(0n);
  });
});
