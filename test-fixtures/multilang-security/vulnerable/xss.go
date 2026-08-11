package vulnerable

import (
	"html/template"
	"net/http"
)

func WriteHTML(writer http.ResponseWriter, request *http.Request) {
	values := request.URL.Query()
	name := values["name"][0]
	page := "<h1>Hello " + name + "</h1>"
	writer.Write([]byte(page))
}

func TrustRequestValue(request *http.Request, value string) template.JS {
	return template.JS(value)
}
