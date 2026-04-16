const { formatResults } = require("../src/format");

const makeVuln = (overrides = {}) => ({
  PkgName: "openssl",
  VulnerabilityID: "CVE-2023-1234",
  Severity: "HIGH",
  Status: "fixed",
  InstalledVersion: "1.0.0",
  FixedVersion: "1.0.1",
  Title: "Test vulnerability",
  ...overrides,
});

const makeResult = (target, vulns = [], type = "debian") => ({
  Target: target,
  Type: type,
  Vulnerabilities: vulns,
});

describe("formatResults — vulns only (default)", () => {
  test("returns no-vulns message when Results is empty", () => {
    expect(formatResults({ Results: [] })).toBe(
      "## Trivy Scan Results\n\nNo vulnerabilities found."
    );
  });

  test("returns no-vulns message when Results is missing", () => {
    expect(formatResults({})).toBe(
      "## Trivy Scan Results\n\nNo vulnerabilities found."
    );
  });

  test("filters out targets with zero vulnerabilities", () => {
    const data = {
      Results: [
        makeResult("clean-image", []),
        makeResult("vuln-image", [makeVuln()]),
      ],
    };
    const output = formatResults(data);
    expect(output).not.toContain("clean-image");
    expect(output).toContain("vuln-image");
  });

  test("renders a markdown table row per vulnerability", () => {
    const data = { Results: [makeResult("my-image", [makeVuln()])] };
    const output = formatResults(data);
    expect(output).toContain(
      "| openssl | CVE-2023-1234 | HIGH | fixed | 1.0.0 | 1.0.1 | Test vulnerability |"
    );
  });

  test("escapes pipe characters in vulnerability titles", () => {
    const data = {
      Results: [makeResult("my-image", [makeVuln({ Title: "foo | bar" })])],
    };
    expect(formatResults(data)).toContain("foo \\| bar");
  });

  test("renders dash for missing FixedVersion", () => {
    const data = {
      Results: [makeResult("my-image", [makeVuln({ FixedVersion: undefined })])],
    };
    expect(formatResults(data)).toContain("| - |");
  });

  test("renders dash for missing Status", () => {
    const data = {
      Results: [makeResult("my-image", [makeVuln({ Status: undefined })])],
    };
    expect(formatResults(data)).toContain("| - |");
  });

  test("renders dash for missing Title", () => {
    const data = {
      Results: [makeResult("my-image", [makeVuln({ Title: undefined })])],
    };
    expect(formatResults(data)).toContain("| - |");
  });

  test("renders a section per vulnerable target", () => {
    const data = {
      Results: [
        makeResult("image-a", [makeVuln({ VulnerabilityID: "CVE-A" })]),
        makeResult("image-b", [makeVuln({ VulnerabilityID: "CVE-B" })]),
      ],
    };
    const output = formatResults(data);
    expect(output).toContain("### image-a");
    expect(output).toContain("### image-b");
    expect(output).toContain("CVE-A");
    expect(output).toContain("CVE-B");
  });
});

describe("formatResults — full summary enabled", () => {
  test("includes a Report Summary table with all targets", () => {
    const data = {
      Results: [
        makeResult("clean-image", []),
        makeResult("vuln-image", [makeVuln()]),
      ],
    };
    const output = formatResults(data, true);
    expect(output).toContain("### Report Summary");
    expect(output).toContain("clean-image");
    expect(output).toContain("vuln-image");
  });

  test("shows 0 vulnerability count for clean targets in summary", () => {
    const data = { Results: [makeResult("clean-image", [])] };
    const output = formatResults(data, true);
    expect(output).toContain("| clean-image | debian | 0 |");
  });

  test("shows correct vulnerability count in summary", () => {
    const data = {
      Results: [makeResult("vuln-image", [makeVuln(), makeVuln()])],
    };
    const output = formatResults(data, true);
    expect(output).toContain("| vuln-image | debian | 2 |");
  });

  test("still renders the detail table for vulnerable targets", () => {
    const data = {
      Results: [makeResult("vuln-image", [makeVuln()])],
    };
    const output = formatResults(data, true);
    expect(output).toContain("CVE-2023-1234");
  });

  test("shows no-vulns message when all targets are clean", () => {
    const data = { Results: [makeResult("clean-image", [])] };
    const output = formatResults(data, true);
    expect(output).toContain("No vulnerabilities found.");
  });
});
