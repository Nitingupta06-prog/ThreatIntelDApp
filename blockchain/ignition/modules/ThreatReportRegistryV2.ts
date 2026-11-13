import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("ThreatReportRegistryV2Module", (m) => {
  const reviewerA = m.getParameter("reviewerA");
  const reviewerB = m.getParameter("reviewerB");
  const reviewerC = m.getParameter("reviewerC");

  const registry = m.contract("ThreatReportRegistryV2", [reviewerA, reviewerB, reviewerC]);

  return { registry };
});
