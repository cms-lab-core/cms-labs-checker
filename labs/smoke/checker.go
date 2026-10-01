package smoke

import (
	"context"

	"github.com/cms-lab-core/cms-labs-checker/checker"
)

type Checker struct{}

func New() *Checker { return &Checker{} }

func (*Checker) Name() string { return "smoke" }

func (*Checker) Aliases() []string { return []string{"example", "local_smoke"} }

func (*Checker) Check(ctx context.Context, environment checker.Environment) (*checker.Result, error) {
	contextTask := checker.NewTask("Session context", "Clabgate passed the attempt and namespace to the checker")
	if environment.AttemptID == "" || environment.SessionNamespace == "" {
		contextTask.AddLog("ATTEMPT_ID or SESSION_NAMESPACE is empty")
	} else {
		contextTask.AddLog("session context is available", "", environment.SessionNamespace).SetCompleted(true)
	}

	cancellationTask := checker.NewTask("Execution context", "The checker execution context is active")
	select {
	case <-ctx.Done():
		cancellationTask.AddLog("execution was cancelled: " + ctx.Err().Error())
	default:
		cancellationTask.AddLog("execution context is active").SetCompleted(true)
	}

	result := checker.NewResult(contextTask, cancellationTask)
	result.Report = "Smoke checker demonstrates one package and one test suite per laboratory."
	return result, nil
}
