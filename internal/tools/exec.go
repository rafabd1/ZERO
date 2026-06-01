package tools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

func Require(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s not found in PATH: install it or set the matching ZERO_*_BIN variable", name)
	}
	return nil
}

func RunLines(ctx context.Context, bin string, args []string, stdin io.Reader, onLine func(string) error) error {
	if err := Require(bin); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if err := onLine(line); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return err
		}
	}
	scanErr := scanner.Err()
	errBytes, _ := io.ReadAll(stderr)
	waitErr := cmd.Wait()

	if scanErr != nil {
		return scanErr
	}
	if waitErr != nil {
		msg := strings.TrimSpace(string(errBytes))
		if msg == "" {
			msg = waitErr.Error()
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}
		return fmt.Errorf("%s failed: %s", bin, msg)
	}
	return nil
}

func RunLinesRetry(ctx context.Context, attempts int, delay time.Duration, bin string, args []string, stdinFactory func() (io.Reader, error), onLine func(string) error) error {
	if attempts < 1 {
		attempts = 1
	}
	if delay <= 0 {
		delay = 2 * time.Second
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		stdin, err := stdinFactory()
		if err != nil {
			return err
		}
		lastErr = RunLines(ctx, bin, args, stdin, onLine)
		if lastErr == nil {
			return nil
		}
		if attempt == attempts || errors.Is(ctx.Err(), context.Canceled) {
			break
		}
		select {
		case <-time.After(delay * time.Duration(attempt)):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return lastErr
}
