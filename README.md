# CMS Labs checker

[![CI](https://github.com/cms-lab-core/cms-labs-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/cms-lab-core/cms-labs-checker/actions/workflows/ci.yml)
[![CodeQL](https://github.com/cms-lab-core/cms-labs-checker/actions/workflows/codeql.yml/badge.svg)](https://github.com/cms-lab-core/cms-labs-checker/actions/workflows/codeql.yml)
[![Container image](https://github.com/cms-lab-core/cms-labs-checker/actions/workflows/images.yml/badge.svg)](https://github.com/cms-lab-core/cms-labs-checker/actions/workflows/images.yml)

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

## Result contract: Pod stdout logs

Checker writes a single framed JSON result to **stdout**. Clabgate reads it
from Kubernetes Pod logs. The termination message file is **not used**.

The JSON model is unchanged: `max_score`, `current_score`,
`result_display`, `report` and `tasks` with independent grading results.
Each log line starts with one `CMS_LABS_CHECKER_RESULT_V1` prefix,
followed by the full-payload SHA-256 and a base64 chunk (at most 2048
characters). Matching hashes verify completion without BEGIN/END markers. Frames up to **1 MiB JSON** are accepted.

This is a **breaking release**: old checker binaries which write only a
termination message are not compatible with the new Clabgate.

For Python, shell or another stack, use the standalone stdlib helper (no Go
runtime or SDK needed):

```bash
python3 scripts/checker_result.py encode < result.json
python3 scripts/checker_result.py decode < result.log > result.json
```

Emit the result once, as the final stdout output; write diagnostic messages to
stderr. Failed checks still return a valid partial-score result and exit zero.
Nonzero exit codes indicate checker infrastructure/runtime errors, not a
student's incorrect answer. There is no termination-message or raw-JSON fallback.

## Local development

```bash
go test ./...
go test ./labs/smoke

ATTEMPT_ID=local \
SESSION_NAMESPACE=lab-local \
TEST_PATH=smoke \
go run ./cmd/checker > build/result.log
```

Build the same container used by Clabgate:

```bash
docker build -t ghcr.io/cms-lab-core/cms-labs-checker:local .
```

## CI and releases

Pull requests run formatting, golangci-lint, race-enabled unit tests, CLI contract
smoke, Docker build/smoke, CodeQL and dependency review. Coverage is retained as
a workflow artifact. Pushes to `main` publish `main` and `sha-*` tags
to `ghcr.io/cms-lab-core/cms-labs-checker`; a Git tag such as `v1.2.3` also
publishes `v1.2.3`, the normalized SemVer tag `1.2.3` and the stable `latest`
alias. Published images include BuildKit provenance and SBOM attestations.

