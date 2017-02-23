/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

func (s *Server) invokeCommand(request *http.Request, stdin io.Reader, workDir string, combined bool, timeout time.Duration, cmdline []string) ([]byte, Response, error) {
	ctx, cancel := context.WithTimeout(request.Context(), timeout)
	defer cancel()
	hangup := &hangupDetector{r: stdin, cancel: cancel}
	if stdin != nil {
		stdin = hangup
	}

	var stdout, stderr bytes.Buffer
	proc := exec.CommandContext(ctx, cmdline[0], cmdline[1:]...)
	proc.Dir = workDir
	proc.Stdin = stdin
	proc.Stdout = &stdout
	proc.Stderr = &stderr
	err := proc.Run()
	if err == nil {
		return stdout.Bytes(), nil, nil
	}
	output := stderr.String()
	if combined {
		output = stdout.String() + output
	}
	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			s.Logr(request, "error: command timed out after %d seconds\nCommand: %s\nOutput:\n%s\n\n",
				timeout/time.Second, formatCmdline(cmdline), output)
		} else {
			s.Logr(request, "client hung up during signing operation")
		}
		return nil, StringResponse(http.StatusGatewayTimeout, "Signing command timed out"), nil
	default:
	}
	s.Logr(request, "error: invoking signing tool: %s\nCommand: %s\nOutput:\n%s\n\n", err, formatCmdline(cmdline), output)
	switch {
	case strings.Contains(stderr.String(), "no certificate of type"):
		return nil, StringResponse(http.StatusBadRequest, "key does not support signatures of this type"), nil
	default:
		return nil, ErrorResponse(http.StatusInternalServerError), nil
	}
}

func appendDigest(cmdline []string, request *http.Request) []string {
	if digest := request.URL.Query().Get("digest"); digest != "" {
		cmdline = append(cmdline, "--digest", digest)
	}
	if filename := request.URL.Query().Get("filename"); filename != "" {
		cmdline = append(cmdline, "--attr", "client.filename="+filename)
	}
	cmdline = append(cmdline,
		"--attr", "client.ip="+GetClientIP(request),
		"--attr", "client.name="+GetClientName(request),
	)
	return cmdline
}

func formatCmdline(cmdline []string) string {
	words := make([]string, len(cmdline))
	for i, word := range cmdline {
		if strings.Index(word, " ") >= 0 {
			word = "\"" + word + "\""
		}
		words[i] = word
	}
	return strings.Join(words, " ")
}

// When a stream is being shovelled into a process' stdin and that stream gets
// an unexpected EOF, the EOF error is not surfaced because the process'
// ExitError takes priority. hangupDetector interposes and cancels the context
// on unexpected EOF so this situation is detectable.
type hangupDetector struct {
	r      io.Reader
	cancel context.CancelFunc
}

func (d *hangupDetector) Read(buf []byte) (n int, err error) {
	n, err = d.r.Read(buf)
	if err == io.ErrUnexpectedEOF {
		d.cancel()
	}
	return
}
