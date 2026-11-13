import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("ThreatReportRegistryAdminModule", (m) => {
  const adminAddress = m.getParameter("adminAddress");

  const registry = m.contract("ThreatReportRegistry");

  m.call(registry, "transferAdmin", [adminAddress]);

  return { registry };
});
