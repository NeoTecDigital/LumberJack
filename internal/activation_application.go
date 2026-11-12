// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"net/http"
	"strings"
)

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
		s.authMiddleware(s.handlePrincipal)(out, req)
	case path == "/notifications" && (method == "GET" || method == "POST"):
		s.authMiddleware(s.handleApplicationNotifications)(out, req)
	case path == "/feed" && (method == "GET" || method == "PATCH"):
		s.authMiddleware(s.HandleFeed)(out, req)
	case path == "/feed/preferences" && (method == "GET" || method == "PATCH"):
		s.authMiddleware(s.HandleFeedPreferences)(out, req)
	case path == "/assets/index" && method == "GET":
		s.authMiddleware(s.HandleAssetsIndex)(out, req)
	case messageOperationRoute(req):
		s.authMiddleware(s.handleMessageOperations)(out, req)
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
