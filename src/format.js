/**
 * Parses Trivy JSON output and returns a markdown string.
 *
 * @param {object} data        - Parsed Trivy JSON
 * @param {boolean} fullSummary - When true, includes targets with 0 vulnerabilities in the summary
 * @returns {string} Markdown formatted results
 */
function formatResults(data, fullSummary = false) {
  const results = data.Results || [];
  const withVulns = results.filter((r) => r.Vulnerabilities?.length > 0);

  if (withVulns.length === 0 && !fullSummary) {
    return "## Trivy Scan Results\n\nNo vulnerabilities found.";
  }

  let md = "## Trivy Scan Results\n\n";

  if (fullSummary) {
    md += "### Report Summary\n\n";
    md += "| Target | Type | Vulnerabilities |\n";
    md += "|--------|------|-----------------|\n";
    for (const result of results) {
      const count = result.Vulnerabilities?.length ?? 0;
      md += `| ${result.Target} | ${result.Type || "-"} | ${count} |\n`;
    }
    md += "\n";
  }

  if (withVulns.length === 0) {
    md += "No vulnerabilities found.";
    return md;
  }

  for (const result of withVulns) {
    md += `### ${result.Target}\n\n`;
    md +=
      "| Library | CVE | Severity | Status | Installed | Fixed | Title |\n";
    md +=
      "|---------|-----|----------|--------|-----------|-------|-------|\n";
    for (const v of result.Vulnerabilities) {
      const title = (v.Title || "-").replace(/\|/g, "\\|");
      md += `| ${v.PkgName} | ${v.VulnerabilityID} | ${v.Severity} | ${v.Status || "-"} | ${v.InstalledVersion} | ${v.FixedVersion || "-"} | ${title} |\n`;
    }
    md += "\n";
  }

  return md;
}

module.exports = { formatResults };
