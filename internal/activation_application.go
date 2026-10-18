// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"net/http"
	"strings"
)

func activationInputHeaders(input ApplicationRequest) http.Header {
	headers := make(http.Header)
	for key, value := range input.Headers {
		headers.Add(key, value)
	}
	return headers
}

func makeApplicationRequest(input ApplicationRequest) (*http.Request, error) {
	req, err := http.NewRequest(input.Method, "http://embedded"+input.Target, bytes.NewReader(input.Body))
	if err != nil {
		return nil, err
	}
	for key, value := range input.Headers {
		req.Header.Set(key, value)
	}
	return req, nil
}

// Route extraction retains the legacy application dispatcher verbatim.
func (s *Server) dispatchApplication(req *http.Request, out *applicationWriter) {
	path, method := req.URL.Path, req.Method
	switch {
	case path == "/session" && method == "POST":
		s.handleApplicationSession(out, req)
	case path == "/session/mfa" && method == "POST":
		s.handleApplicationSessionMFA(out, req)
	case path == "/session" && (method == "GET" || method == "DELETE"):
		s.authMiddleware(s.handleApplicationSession)(out, req)
	case path == "/session/activity" && method == "POST":
		s.authMiddleware(s.handleApplicationActivity)(out, req)
	case path == "/principal" && method == "GET":
		s.authMiddleware(s.handleAuthenticatedPrincipal)(out, req)
	case path == "/activation/probe":
		s.authMiddleware(s.handleActivationProbe)(out, req)
	case path == "/notifications" && (method == "GET" || method == "POST"):
		s.authMiddleware(s.handleApplicationNotifications)(out, req)
	case path == "/changes" && method == "POST":
		s.authMiddleware(s.handleApplicationChanges)(out, req)
	default:
		s.routes().ServeHTTP(out, req)
	}
}

func applicationOutput(out *applicationWriter) ApplicationResponse {
	if out.overflow {
		return applicationError(413, "Response exceeds application limit")
	}
	if out.status == 0 {
		out.status = 200
	}
	headers := map[string]string{}
	for key, value := range out.header {
		headers[key] = strings.Join(value, ", ")
	}
	return ApplicationResponse{Status: out.status, Headers: headers, Body: out.body.Bytes()}
}
