package tools

import (
	"bufio"
	"bytes"
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

type TimeoutError struct {
	Bin     string
	Args    []string
	Timeout time.Duration
}

func (e TimeoutError) Error() string {
	return fmt.Sprintf("%s timed out after %s", e.Bin, e.Timeout)
}

func IsTimeout(err error) bool {
	var timeoutErr TimeoutError
	return errors.As(err, &timeoutErr)
}

func TimeoutDuration(err error) (time.Duration, bool) {
	var timeoutErr TimeoutError
	if !errors.As(err, &timeoutErr) {
		return 0, false
	}
	return timeoutErr.Timeout, true
}

func RunLines(ctx context.Context, bin string, args []string, stdin io.Reader, onLine func(string) error) error {
	return RunLinesWithTimeout(ctx, 0, bin, args, stdin, onLine)
}

func RunLinesWithTimeout(ctx context.Context, timeout time.Duration, bin string, args []string, stdin io.Reader, onLine func(string) error) error {
	if err := Require(bin); err != nil {
		return err
	}
	runCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(runCtx, bin, args...)
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

	stdoutErr := make(chan error, 1)
	stderrErr := make(chan error, 1)
	var errBuf bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if err := onLine(line); err != nil {
				_ = cmd.Process.Kill()
				stdoutErr <- err
				return
			}
		}
		stdoutErr <- scanner.Err()
	}()
	go func() {
		_, err := io.Copy(&errBuf, stderr)
		stderrErr <- err
	}()
	scanErr := <-stdoutErr
	errReadErr := <-stderrErr
	waitErr := cmd.Wait()

	if scanErr != nil {
		return scanErr
	}
	if errReadErr != nil {
		return errReadErr
	}
	if waitErr != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return TimeoutError{Bin: bin, Args: append([]string(nil), args...), Timeout: timeout}
		}
		if errors.Is(runCtx.Err(), context.Canceled) {
			return runCtx.Err()
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
