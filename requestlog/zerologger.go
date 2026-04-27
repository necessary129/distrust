package requestlog

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
)

// Zerologger is a chi middleware that logs one structured line per request at
// Info level (so it appears under the project's documented `log.level: info`
// default). It pulls the request ID off the chi/middleware.RequestID context
// when available and surfaces it both in the log line and as `X-Request-ID`
// on the response so operators can correlate user reports with logs.
func Zerologger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		reqID := middleware.GetReqID(r.Context())
		if reqID != "" {
			ww.Header().Set("X-Request-ID", reqID)
		}
		start := time.Now()
		defer func() {
			log.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("from", r.RemoteAddr).
				Str("request_id", reqID).
				Dur("duration", time.Since(start)).
				Int("status", ww.Status()).
				Msg("request finished")
		}()
		next.ServeHTTP(ww, r)
	})

}
