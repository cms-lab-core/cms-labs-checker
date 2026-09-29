# CMS Labs checker

[![CI](https://github.com/maintainer64/cms-labs-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/maintainer64/cms-labs-checker/actions/workflows/ci.yml)
[![CodeQL](https://github.com/maintainer64/cms-labs-checker/actions/workflows/codeql.yml/badge.svg)](https://github.com/maintainer64/cms-labs-checker/actions/workflows/codeql.yml)
[![Container image](https://github.com/maintainer64/cms-labs-checker/actions/workflows/images.yml/badge.svg)](https://github.com/maintainer64/cms-labs-checker/actions/workflows/images.yml)

Standalone checker image for Kubernetes laboratory sessions managed by Clabgate.
The platform lives in `cms-labs-api`; this repository owns laboratory-specific
checks and their unit tests.

## Why packages instead of Go plugins

Each laboratory is a regular package under `labs/<name>`. Go plugins require the
host and plugin to be built with exactly compatible Go/toolchain and dependency
versions, have limited platform support, and complicate reproducible container
builds. A compile-time registry gives every lab isolated source and tests while
keeping one small static executable and one auditable image.

## Repository layout

```text
checker/             stable Result/Task/Log model, LabChecker interface, registry
labs/smoke/          one laboratory implementation and its checker_test.go
labs/sdnlab5/        runnable SDN_Lab_5 example checks
internal/catalog/    explicit list of packages included in the image
cmd/checker/         Kubernetes/CLI entry point
```

Clabgate starts this image with `SESSION_ID`, `ATTEMPT_ID`,
`SESSION_NAMESPACE`, `LAB_PATH`, and `TEST_PATH`. Selection order is:

1. `-lab` command-line override;
2. `TEST_PATH` basename without extension;
3. `LAB_PATH` basename without extension.

For example, `TEST_PATH=checks/sdn_lab_4.go` selects a checker named
`sdn_lab_4`. If CMS does not set `test_path`, `labs/smoke` selects `smoke`.

## Add a laboratory

1. Create `labs/my_lab/checker.go` and implement `checker.LabChecker`.
2. Put all unit/integration-style tests for that lab in
   `labs/my_lab/checker_test.go`.
3. Register `my_lab.New()` in `internal/catalog/catalog.go`.
4. Run `go test ./labs/my_lab` while developing and `go test ./...` before a PR.

An unmet student requirement is not a Go error: append a structured log and
leave the task with `complete=false`. Return an error only when the checker
itself could not execute, for example because a required service was unavailable.

```go
func (*Checker) Check(ctx context.Context, env checker.Environment) (*checker.Result, error) {
    ssh := checker.NewTask("SSH", "router accepts SSH")
    if err := probeSSH(ctx, "r1."+env.SessionNamespace+".svc.cluster.local"); err != nil {
        ssh.AddLog(err.Error(), "r1", env.SessionNamespace)
    } else {
        ssh.AddLog("connected", "r1", env.SessionNamespace).SetCompleted(true)
    }
    return checker.NewResult(ssh), nil
}
```

## Result contract

The executable writes exactly one JSON object to `/dev/termination-log`:

```json
{
  "max_score": 2,
  "current_score": 1,
  "result_display": "1/2 checks passed",
  "report": "Optional Markdown summary",
  "tasks": [{
    "title": "SSH",
    "description": "router accepts SSH",
    "logs": [{"node": "r1", "namespace": "lab-123", "message": "connected"}],
    "complete": true
  }]
}
```

Kubernetes limits a termination message to 4096 bytes, and `WriteResult`
rejects larger output instead of allowing truncated JSON. Keep structured task
messages concise and write verbose diagnostics to stdout/stderr. Clabgate adds
trusted `check_id` and the last 64 KiB of Pod output before sending the result to
CMS and Moodle/LTI.

## Local development

```bash
go test ./...
go test ./labs/smoke

ATTEMPT_ID=local \
SESSION_NAMESPACE=lab-local \
TEST_PATH=smoke \
go run ./cmd/checker -output build/result.json
```

Build the same container used by Clabgate:

```bash
docker build -t ghcr.io/maintainer64/cms-labs-checker:local .
```

## CI and releases

Pull requests run formatting, golangci-lint, race-enabled unit tests, CLI contract
smoke, Docker build/smoke, CodeQL and dependency review. Coverage is retained as
a workflow artifact. Pushes to `main` publish `main`, `sha-*` and `latest` tags
to `ghcr.io/maintainer64/cms-labs-checker`; a Git tag such as `v1.2.3` also
publishes both `v1.2.3` and the normalized SemVer tag `1.2.3`. Published images include BuildKit
provenance and SBOM attestations.
