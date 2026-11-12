// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
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
// dispatchApplication serves one application-transport request: the application table first (the
// engine's application-only routes, then the extensions'), then the HTTP mux.
func (s *Server) dispatchApplication(req *http.Request, out *applicationWriter) {
	application := s.applicationRouter()
	var match mux.RouteMatch
	if application.Match(req, &match) {
		application.ServeHTTP(out, req)
		return
	}
	s.routesFor(transportApplication).ServeHTTP(out, req)
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
