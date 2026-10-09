package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cms-lab-core/cms-labs-checker/checker"
	"github.com/cms-lab-core/cms-labs-checker/internal/catalog"
)

func main() {
	if err := run(); err != nil {
		log.Printf("checker failed: %v", err)
		os.Exit(1)
	}
}

func run() error {
	selector := flag.String("lab", "", "checker name; overrides TEST_PATH and LAB_PATH")
	list := flag.Bool("list", false, "list registered laboratory checkers")
	flag.Parse()

	registry, err := catalog.New()
	if err != nil {
		return err
	}
	if *list {
		fmt.Println(strings.Join(registry.Names(), "\n"))
		return nil
	}

	environment := checker.Environment{
		SessionID:        os.Getenv("SESSION_ID"),
		AttemptID:        os.Getenv("ATTEMPT_ID"),
		SessionNamespace: os.Getenv("SESSION_NAMESPACE"),
		LabPath:          os.Getenv("LAB_PATH"),
		TestPath:         os.Getenv("TEST_PATH"),
	}
	lab, err := registry.Select(*selector, environment.TestPath, environment.LabPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	result, err := lab.Check(ctx, environment)
	if err != nil {
		return fmt.Errorf("run %s checker: %w", lab.Name(), err)
	}
	if err := checker.WriteResult(os.Stdout, result); err != nil {
		return err
	}
	log.Printf("checker %s completed with score %g/%g", lab.Name(), result.CurrentScore, result.MaxScore)
	return nil
}
