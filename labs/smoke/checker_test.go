package smoke

import (
	"context"
	"testing"

	"github.com/cms-lab-core/cms-labs-checker/checker"
)

func TestCheckerPassesWithSessionContext(t *testing.T) {
	result, err := New().Check(context.Background(), checker.Environment{
		AttemptID: "attempt-1", SessionNamespace: "lab-attempt-1",
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.CurrentScore != 2 || result.MaxScore != 2 {
		t.Fatalf("score = %g/%g, want 2/2", result.CurrentScore, result.MaxScore)
	}
	if result.Tasks[0].Logs[0].Namespace != "lab-attempt-1" {
		t.Fatalf("namespace log was not preserved: %+v", result.Tasks[0].Logs[0])
	}
}

func TestCheckerReportsMissingSessionContextAsStudentVisibleFailure(t *testing.T) {
	result, err := New().Check(context.Background(), checker.Environment{})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.CurrentScore != 1 || result.Tasks[0].Complete {
		t.Fatalf("missing context was not reported as failed task: %+v", result)
	}
}
