package safe

import (
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"strconv"
)

func WriteEscaped(writer http.ResponseWriter, request *http.Request) {
	name := request.URL.Query().Get("name")
	fmt.Fprintf(writer, "<h1>Hello %s</h1>", html.EscapeString(name))
}

func WriteJSON(writer http.ResponseWriter, request *http.Request) {
	data := request.FormValue("data")
	encoded, _ := json.Marshal(data)
	writer.Write(encoded)
}

func WriteInteger(writer http.ResponseWriter, request *http.Request) {
	value, _ := strconv.Atoi(request.FormValue("id"))
	writer.Write([]byte(strconv.Itoa(value)))
}

func TrustEscapedValue(request *http.Request, value string) template.HTML {
	return template.HTML(html.EscapeString(value))
}
