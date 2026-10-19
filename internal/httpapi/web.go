package httpapi

import (
	"io/fs"
	"net/http"

	webassets "shadowedge/web"
)

var webFS = webassets.FS

func (s *Server) vendorHandler() http.Handler {
	sub, err := fs.Sub(webassets.FS, "vendor")
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.FileServer(http.FS(sub))
}
