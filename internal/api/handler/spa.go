package handler

import (
	"io/fs"
	"net/http"
	"strings"

	"mibee-steward/web"
)

// NewSPAHandler returns an http.Handler that serves the embedded SPA static files
// with proper caching headers and SPA fallback routing.
func NewSPAHandler() http.Handler {
	// Get sub-filesystem for the dist directory
	distFS, err := fs.Sub(web.DistFS, "dist")
	if err != nil {
		panic("failed to get dist sub-filesystem: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(distFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")

		// Serve static assets with immutable cache headers
		if strings.HasPrefix(r.URL.Path, "/_app/") || strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			fileServer.ServeHTTP(w, r)
			return
		}

		// Try to serve the actual file first
		if path != "" {
			if f, err := distFS.Open(path); err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}

		// Fallback to index.html for SPA routing
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}
