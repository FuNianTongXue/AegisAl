package safe

import (
	"archive/zip"
	"bufio"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

func OpenSafeFile(writer http.ResponseWriter, request *http.Request, root string) {
	name := filepath.Base(request.FormValue("name"))
	_, _ = os.Open(filepath.Join(root, name))
}

func OpenSafePathBase(request *http.Request, root string) {
	name := path.Base(request.FormValue("name"))
	_, _ = os.Open(filepath.Join(root, name))
}

func OpenSafeInteger(request *http.Request, root string) {
	identifier, _ := strconv.Atoi(request.FormValue("id"))
	_, _ = os.Open(filepath.Join(root, strconv.Itoa(identifier)))
}

func OpenSafeCleanedRoot(request *http.Request, root string) {
	name := filepath.Clean("/" + strings.Trim(request.URL.Path, "/"))
	_, _ = os.Open(filepath.Join(root, strings.Trim(name, "/")))
}

func OpenSafeTerminal(root string) {
	reader := bufio.NewReader(os.Stdin)
	name, _ := reader.ReadString('\n')
	_, _ = os.Open(filepath.Join(root, filepath.Base(strings.TrimSpace(name))))
}

func ExtractSafeEntry(entry *zip.File, root string) error {
	target := filepath.Join(root, filepath.Base(entry.Name))
	output, err := os.Create(target)
	if err != nil {
		return err
	}
	return output.Close()
}

func PublicFileServer() http.Handler {
	return http.FileServer(http.Dir("/srv/public"))
}

func BuildSafeRequest(writer http.ResponseWriter, request *http.Request, baseURL string) {
	challenge := url.QueryEscape(request.FormValue("challenge"))
	_, _ = http.NewRequest(http.MethodGet, baseURL+"?challenge="+challenge, nil)
}
