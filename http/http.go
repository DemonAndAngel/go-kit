package http

import "net/http"

func ServeHandler(addr string, handler http.Handler) error {
	return http.ListenAndServe(addr, handler)
}

func Serve(svc *http.Server) error {
	return svc.ListenAndServe()
}
