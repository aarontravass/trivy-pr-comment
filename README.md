# trivy-pr-comment

A composite GitHub Action that reads a [Trivy](https://github.com/aquasecurity/trivy) JSON scan result and posts the vulnerabilities as a PR comment.

By default only targets with vulnerabilities are shown. An optional full summary table of all scanned targets can be enabled.

## Usage

```yaml
- name: Scan container image with Trivy
  uses: aquasecurity/trivy-action@v0.35.0
  continue-on-error: true
  with:
    image-ref: my-image:${{ github.sha }}
    severity: HIGH,CRITICAL
    exit-code: 1
    format: json
    output: trivy-results.json

- name: Post Trivy results as PR comment
  if: always()
  uses: aarontravass/trivy-pr-comment@v1
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `results-file` | No | `trivy-results.json` | Path to the Trivy JSON output file |
| `full-summary` | No | `false` | When `true`, prepends a summary table of all scanned targets including those with 0 vulnerabilities |

## Examples

### Vulnerabilities only (default)

```yaml
- uses: aarontravass/trivy-pr-comment@v1
```

### With full summary

```yaml
- uses: aarontravass/trivy-pr-comment@v1
  with:
    full-summary: "true"
```

### Custom results file path

```yaml
- uses: aarontravass/trivy-pr-comment@v1
  with:
    results-file: path/to/trivy-results.json
```

## Required permissions

The calling workflow must have `pull-requests: write`:

```yaml
permissions:
  pull-requests: write
```

## Development

```bash
npm install
npm test
```

Tags are created automatically on push to `main` using [conventional commits](https://www.conventionalcommits.org/):

| Commit prefix | Version bump |
|---|---|
| `fix:` | patch |
| `feat:` | minor |
| `feat!:` / `BREAKING CHANGE` | major |
