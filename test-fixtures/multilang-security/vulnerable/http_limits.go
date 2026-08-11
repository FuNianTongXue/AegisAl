package vulnerable

import "net/http"

func StartServer() error {
	return (&http.Server{Addr: ":8080"}).ListenAndServe()
}

func ParseUpload(writer http.ResponseWriter, request *http.Request) error {
	return request.ParseMultipartForm(32 << 20)
}
