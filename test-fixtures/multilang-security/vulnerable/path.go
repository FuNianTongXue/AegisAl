package vulnerable

import (
	"archive/zip"
	"bufio"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func OpenURLPath(request *http.Request) {
	name := filepath.Clean(request.URL.Path)
	_, _ = os.Open(filepath.Join("/srv/files", strings.Trim(name, "/")))
}

func OpenTerminalPath() {
	reader := bufio.NewReader(os.Stdin)
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	_, _ = os.Open(filepath.Join("/srv/files", name))
}

func ServeRequestPath(writer http.ResponseWriter, request *http.Request) {
	http.ServeFileFS(writer, request, os.DirFS("/srv/files"), request.FormValue("name"))
}

func RootFileServer() http.Handler {
	return http.FileServer(http.Dir("/"))
}

func ExtractEntry(entry *zip.File, root string) error {
	target := filepath.Join(root, entry.Name)
	output, err := os.Create(target)
	if err != nil {
		return err
	}
	return output.Close()
}
