package safe

import (
	"net/http"
	"time"
)

func StartServer() error {
	return (&http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
	}).ListenAndServe()
}

func ParseUpload(writer http.ResponseWriter, request *http.Request) error {
	request.Body = http.MaxBytesReader(writer, request.Body, 40<<20)
	return request.ParseMultipartForm(32 << 20)
}
