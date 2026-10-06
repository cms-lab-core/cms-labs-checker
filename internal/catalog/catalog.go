package catalog

import (
	"github.com/cms-lab-core/cms-labs-checker/checker"
	"github.com/cms-lab-core/cms-labs-checker/labs/cn000"
	"github.com/cms-lab-core/cms-labs-checker/labs/cn001"
	"github.com/cms-lab-core/cms-labs-checker/labs/sdnlab5"
	"github.com/cms-lab-core/cms-labs-checker/labs/smoke"
)

// New is the compile-time catalog. A new laboratory owns a package under labs/
// and is registered here. This keeps builds static and portable while allowing
// every lab to have isolated implementation and unit tests.
func New() (*checker.Registry, error) {
	return checker.NewRegistry(
		cn000.New(),
		cn001.New(),
		sdnlab5.New(),
		smoke.New(),
	)
}
