from __future__ import annotations

import unittest

from app.go_semantic_analyzer import analyze_go_semantics


class GoSemanticAnalyzerTests(unittest.TestCase):
    def test_reports_discarded_context_cancel(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import "context"
func run(parent context.Context) {
    child, _ := context.WithCancel(parent)
    _ = child
}
""",
                }
            ]
        )

        self.assertIn(
            "secflow.go.semantic.context-cancel-leak",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_accepts_deferred_or_returned_cancel(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import "context"
func local(parent context.Context) {
    child, cancel := context.WithCancel(parent)
    defer cancel()
    _ = child
}
func owned(parent context.Context) (context.Context, context.CancelFunc) {
    child, cancel := context.WithCancel(parent)
    return child, cancel
}
func aliased(parent context.Context) {
    _, cancel := context.WithCancel(parent)
    cleanup := cancel
    defer cleanup()
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.context-cancel-leak",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_accepts_package_cancel_released_by_another_function(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import "context"
var cancel context.CancelFunc
func init() {
    _, cancel = context.WithCancel(context.Background())
}
func shutdown() {
    cancel()
}
""",
                }
            ]
        )

        self.assertFalse(result["findings"])

    def test_reports_cancel_discarded_through_blank_tuple(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import (
    "context"
    "time"
)
func run(parent context.Context) {
    _, cancel1 := context.WithTimeout(parent, time.Second)
    _, cancel2 := context.WithTimeout(parent, time.Second)
    _, _ = cancel1, cancel2
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.context-cancel-leak"
        ]
        self.assertEqual(len(findings), 2)

    def test_reports_cancel_transferred_to_unreleased_field(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import (
    "context"
    "time"
)
type Task struct {
    cancelFn context.CancelFunc
}
func (t *Task) Execute(ctx context.Context) {
    childCtx, cancel := context.WithTimeout(ctx, time.Second)
    t.cancelFn = cancel
    _ = childCtx
}
func run() {
    // Never calls t.cancelFn()
}
""",
                }
            ]
        )

        self.assertIn(
            "secflow.go.semantic.context-cancel-leak",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_accepts_cancel_transferred_to_released_field(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import (
    "context"
    "time"
)
type Task struct {
    cancelFn context.CancelFunc
}
func (t *Task) Execute(ctx context.Context) {
    childCtx, cancel := context.WithTimeout(ctx, time.Second)
    t.cancelFn = cancel
    _ = childCtx
}
func (t *Task) Stop() {
    t.cancelFn()
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.context-cancel-leak",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_package_cancel_transfer_without_release(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import "context"
var cancel context.CancelFunc
func init() {
    ctx, c := context.WithCancel(context.Background())
    cancel = c
    _ = ctx
}
func main() {
    // Never calls cancel()
}
""",
                }
            ]
        )

        self.assertIn(
            "secflow.go.semantic.context-cancel-leak",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_detached_background_context_in_goroutine(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import (
    "context"
    "net/http"
)
func helper() {
    _ = context.Background()
}
func bad(ctx context.Context) {
    bg := context.TODO()
    go func(c context.Context) {
        _ = c
    }(bg)
    go helper()
}
func fromRequest(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    _ = ctx
    go func() {
        _ = context.Background()
    }()
}
func ignoredRequest(w http.ResponseWriter, r *http.Request) {
    _ = r.Context()
    go func() {
        _ = context.Background()
    }()
}
func ok(ctx context.Context) {
    go func(c context.Context) {
        _ = c
    }(ctx)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.detached-background-context"
        ]
        self.assertEqual(len(findings), 3)

    def test_reports_unreleased_named_cancel_and_context_ignorant_loop(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import "context"
func run(parent context.Context) {
    child, cancel := context.WithCancel(parent)
    _ = child
    _ = cancel
    for {
        doWork()
    }
}
func doWork() {}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.context-cancel-leak"
        ]
        self.assertGreaterEqual(len(findings), 2)

    def test_accepts_loop_that_observes_context(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import "context"
func run(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
    }
}
""",
                }
            ]
        )

        self.assertFalse(result["findings"])

    def test_accepts_bounded_or_blocking_context_loops(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import "context"
func bounded(ctx context.Context, max int) {
    for {
        if max <= 0 { break }
        max--
    }
}
func blocking(ctx context.Context, ch <-chan int) {
    for {
        select {
        case <-ch:
        }
    }
}
""",
                }
            ]
        )

        self.assertFalse(result["findings"])

    def test_reports_math_rand_aliases_without_flagging_crypto_rand(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "random.go",
                    "content": """
package sample
import (
    "crypto/rand"
    mrand "math/rand"
    randv2 "math/rand/v2"
)
func run() {
    _, _ = rand.Read(nil)
    _ = mrand.Int31()
    _ = randv2.IntN(10)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.weak-math-random"
        ]
        self.assertEqual([item["sink"]["line"] for item in findings], [10, 11])
        self.assertEqual([item["source"]["line"] for item in findings], [5, 6])

    def test_ignores_conflicting_math_rand_aliases(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "random.go",
                    "content": """
package sample
import (
    mrand "math/rand"
    mrand "math/rand/something"
)
func run() {
    _ = mrand.Int()
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.weak-math-random",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_weak_hash_aliases(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "hash.go",
                    "content": """
package sample
import (
    "golang.org/x/crypto/md4"
    rmd "golang.org/x/crypto/ripemd160"
    "golang.org/x/crypto/sha3"
)
func run() {
    _ = md4.New()
    _ = rmd.New()
    _ = sha3.New224()
    _ = sha3.Sum224(nil)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.weak-hash"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [9, 10, 11, 12])

    def test_reports_insecure_tls_config_literals_and_constants(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "tls.go",
                    "content": """
package sample
import "crypto/tls"
const skipVerify = !false
var lowMax uint16 = tls.VersionTLS10
func run() {
    _ = &tls.Config{InsecureSkipVerify: skipVerify}
    _ = &tls.Config{PreferServerCipherSuites: !true}
    _ = &tls.Config{MinVersion: tls.VersionTLS10}
    _ = &tls.Config{MaxVersion: lowMax}
    _ = &tls.Config{
        Rand: zeroSource{},
        CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
    }
    server.TLS = &tls.Config{Rand: zeroSource{}}
    mTLSConfig := &tls.Config{}
    mTLSConfig.InsecureSkipVerify = true
    mTLSConfig.MinVersion = tls.VersionTLS11
}
type zeroSource struct{}
func (zeroSource) Read(b []byte) (int, error) { return len(b), nil }
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.insecure-tls-config"
        ]
        self.assertEqual(len(findings), 8)
        self.assertTrue(
            any("MinVersion" in item["sink"]["snippet"] and "CWE-319" in item["cwes"] for item in findings)
        )

    def test_accepts_secure_tls_config_literals_and_aliases(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "tls.go",
                    "content": """
package sample
import (
    "crypto/tls"
    cryptotls "crypto/tls"
)
const MinVer = tls.VersionTLS13
func run() {
    _ = &tls.Config{InsecureSkipVerify: !true}
    _ = &tls.Config{MinVersion: tls.VersionTLS12}
    _ = &tls.Config{MaxVersion: 0}
    _ = &tls.Config{Rand: rand.Reader}
    _ = cryptotls.Config{MinVersion: cryptotls.VersionTLS12}
    _ = tls.Config{MinVersion: MinVer}
    mTLSConfig := &tls.Config{}
    mTLSConfig.InsecureSkipVerify = false
    mTLSConfig.MinVersion = tls.VersionTLS12
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.insecure-tls-config",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_plaintext_transport_url_flows(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "transport.go",
                    "content": """
package sample
func bad() {
    url := "ftp://example.com"
    ftp.Dial(url)
    const twitterApi = "http://api.twitter.com/1.1/"
    base := sling.New().Base(twitterApi)
    _ = base
}
func ok() {
    safe := "sftp://example.com"
    ftp.Connect(safe)
    local := "http://127.0.0.1/"
    _ = sling.New().Get(local)
    _ = sling.New().Post("https://example.com")
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.plaintext-transport"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [5, 7])

    def test_reports_md5_password_hash_flow(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "password.go",
                    "content": """
package sample
import "crypto/md5"
func bad(user *User, pwtext string) {
    h := md5.New()
    h.Write([]byte(pwtext))
    user.setPassword(h.Sum(nil))
}
func ok(user *User, pwtext string) {
    h := md5.New()
    h.Write([]byte(pwtext))
    user.setSomethingElse(h.Sum(nil))
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.md5-password-hash"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("setPassword", findings[0]["sink"]["snippet"])
        self.assertIn("md5.New", findings[0]["source"]["snippet"])

    def test_reports_jwt_none_algorithm(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "jwt.go",
                    "content": """
package sample
import jwt "github.com/dgrijalva/jwt-go"
func bad(claims jwt.Claims) {
    _ = jwt.NewWithClaims(jwt.SigningMethodNone, claims)
}
func ok(claims jwt.Claims) {
    _ = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.jwt-none-algorithm"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("CWE-327", findings[0]["cwes"])

    def test_reports_cgi_serve(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "cgi.go",
                    "content": """
package sample
import "net/http/cgi"
func bad() {
    cgi.Serve(nil)
}
""",
                }
            ]
        )

        self.assertIn(
            "secflow.go.semantic.cgi-serve",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_directory_listing_file_server_flow(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "files.go",
                    "content": """
package sample
import "net/http"
func bad() {
    fs := http.FileServer(http.Dir(""))
    http.Handle("/files", fs)
    http.ListenAndServe(":9000", fs)
}
func ok() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
    http.ListenAndServe(":9000", mux)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.directory-listing"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [6, 7])

    def test_reports_dynamic_trusted_template_types(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "template.go",
                    "content": """
package sample
import (
    "fmt"
    "html/template"
)
func bad(value string) {
    _ = template.HTML(value)
    const a template.HTML = fmt.Sprintf("<a href=%q>link</a>", value)
}
func ok() {
    _ = template.HTML("<b>static</b>" + "<i>literal</i>")
    const script template.JS = "{foo: 'bar'}"
    var css template.CSS = "a { text-decoration: underline; } "
    _ = css
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.trusted-template-type"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [8, 9])

    def test_reports_unsafe_deserialization_flows(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "deserialize.go",
                    "content": """
package sample
import (
    "encoding/gob"
    "encoding/json"
    "encoding/xml"
    "net/http"
    "strings"
)
type User struct{ Name string }
func interfaceTarget(data []byte) {
    var result interface{}
    json.Unmarshal(data, &result)
}
func fromRequest(w http.ResponseWriter, r *http.Request) {
    data := r.FormValue("payload")
    var cfg User
    xml.Unmarshal([]byte(data), &cfg)
    dec := gob.NewDecoder(strings.NewReader(data))
    dec.Decode(&cfg)
}
func ok(w http.ResponseWriter, r *http.Request) {
    data := r.FormValue("payload")
    var user User
    json.Unmarshal([]byte(data), &user)
    dec := gob.NewDecoder(strings.NewReader("static"))
    dec.Decode(&user)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.unsafe-deserialization"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [13, 18, 20])

    def test_reports_range_variable_address_without_pointer_slice_field_false_positive(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "range.go",
                    "content": """
package sample
type item struct{ name string }
func badValue(items []item) {
    for _, item := range items {
        _ = &item.name
    }
}
func badPointerVariable(items []*item) {
    for _, item := range items {
        _ = &item
    }
}
func okPointerField() {
    items := []*item{{name: "a"}}
    for _, item := range items {
        _ = &item.name
    }
}
func okIndexedAssignment() {
    ranged := [1]int{1}
    var accessed [1]*int
    for i, r := range ranged {
        accessed[i] = &r
    }
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.range-variable-address"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [6, 11])

    def test_reports_interprocedural_slice_capacity_violation(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "bounds.go",
                    "content": """
package sample
func bad() {
    s := make([]int, 0, 4)
    doStuff(s)
}
func ok() {
    s := make([]int, 0, 16)
    doStuff(s)
}
func doStuff(x []int) {
    _ = x[:10]
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.interprocedural-slice-out-of-bounds"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("doStuff(s)", findings[0]["source"]["snippet"])

    def test_reports_log_injection_without_structured_attr_false_positive(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "log.go",
                    "content": """
package sample
import (
    "encoding/json"
    "log"
    "log/slog"
    "net/http"
    "os"
    "strconv"
)
func bad(r *http.Request) {
    msg := r.URL.Query().Get("msg")
    slog.Warn(msg)
    username := r.FormValue("user")
    log.Printf("User logged in: %s", username)
    input := os.Args[1]
    log.Println("Processing:", input)
}
func ok(r *http.Request) {
    ext := r.URL.Query().Get("ext")
    slog.Warn("Error getting FS to serve", "ext", ext)
    data := r.FormValue("data")
    jsonData, _ := json.Marshal(data)
    log.Printf("Received: %s", jsonData)
    id := r.FormValue("id")
    num, _ := strconv.Atoi(id)
    log.Printf("Processing ID: %d", num)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.log-injection"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [13, 15, 17])

    def test_reports_ssrf_for_tainted_host_not_tainted_path(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "ssrf.go",
                    "content": """
package sample
import (
    "fmt"
    "net/http"
)
func bad(r *http.Request) {
    target := r.URL.Query().Get("url")
    http.Get(target) //nolint:errcheck
    host := r.URL.Query().Get("proxy")
    url := "https://" + host + "/api"
    client := &http.Client{}
    client.Post(url, "application/json", r.Body)
    other := fmt.Sprintf("https://%v/api", r.URL.Query().Get("proxy"))
    client.Post(other, "application/json", r.Body)
}
func ok(r *http.Request) {
    path := r.URL.Query().Get("proxy")
    url := "https://example.com/" + path
    client := &http.Client{}
    client.Post(url, "application/json", r.Body)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.ssrf"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [9, 13, 15])

    def test_reports_open_redirect_from_request_host(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "redirect.go",
                    "content": """
package sample
import (
    "fmt"
    "net/http"
)
func bad(w http.ResponseWriter, req *http.Request) {
    target := fmt.Sprintf("https://%s/path", req.Host)
    http.Redirect(w, req, target, http.StatusTemporaryRedirect)
}
func alsoBad(w http.ResponseWriter, req *http.Request) {
    target := "https://" + req.Host + "/path"
    http.Redirect(w, req, target, http.StatusTemporaryRedirect)
}
func ok(w http.ResponseWriter, req *http.Request) {
    target := "https://example.com/" + req.URL.Path
    http.Redirect(w, req, target, http.StatusTemporaryRedirect)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.open-redirect"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [9, 13])

    def test_reports_ssti_and_formatted_sql(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "template_sql.go",
                    "content": """
package sample
import (
    "database/sql"
    "fmt"
    "html/template"
    "net/http"
    "strconv"
)
func ssti(w http.ResponseWriter, req *http.Request) {
    query := req.URL.Query().Get("query")
    text := fmt.Sprintf("<p>%s</p>", query)
    tmpl := template.New("hello")
    tmpl.Parse(text)
}
func sqlHandler(db *sql.DB, r *http.Request, username string) {
    query := fmt.Sprintf("%s AND INSERT into users (username, password)", username)
    db.Exec(query)
}
func ok(w http.ResponseWriter, req *http.Request, db *sql.DB) {
    text := fmt.Sprintf("<p>%s</p>", "constant")
    tmpl := template.New("hello")
    tmpl.Parse(text)
    query := fmt.Sprintf("INSERT into users values(%s)", "constant")
    db.Exec(query)
}
func safeNumeric(db *sql.DB, r *http.Request) {
    id, _ := strconv.Atoi(r.FormValue("id"))
    query := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)
    db.Query(query)
}
""",
                }
            ]
        )

        self.assertEqual(
            [item["source"]["line"] for item in result["findings"] if item["rule_id"] == "secflow.go.semantic.ssti"],
            [12],
        )
        self.assertEqual(
            [item["source"]["line"] for item in result["findings"] if item["rule_id"] == "secflow.go.semantic.formatted-sql-injection"],
            [17],
        )

    def test_reports_cookie_options_and_plain_grpc_server(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "cookies_grpc.go",
                    "content": """
package sample
import (
    "crypto/x509"
    "net/http"
    "github.com/gorilla/sessions"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)
func cookies(session *sessions.Session) {
    session.Options = &sessions.Options{
        Path: "/",
        HttpOnly: false,
        Secure: false,
        SameSite: http.SameSiteNoneMode,
    }
    session.Options = &sessions.Options{
        HttpOnly: true,
        Secure: true,
        SameSite: http.SameSiteStrictMode,
    }
}
func grpcServers(pool *x509.CertPool) {
    grpc.NewServer()
    grpc.NewServer(grpc.Creds(credentials.NewClientTLSFromCert(pool, "")))
}
""",
                }
            ]
        )

        rules = {item["rule_id"] for item in result["findings"]}
        self.assertIn("secflow.go.semantic.session-cookie-missing-httponly", rules)
        self.assertIn("secflow.go.semantic.session-cookie-missing-secure", rules)
        self.assertIn("secflow.go.semantic.session-cookie-samesite-none", rules)
        self.assertIn("secflow.go.semantic.grpc-insecure-server", rules)
        self.assertEqual(
            len([item for item in result["findings"] if item["rule_id"] == "secflow.go.semantic.grpc-insecure-server"]),
            1,
        )

    def test_reports_bind_all_interfaces_and_redirect_sensitive_headers(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "net.go",
                    "content": """
package sample
import (
    "net"
    "net/http"
)
const addr = ":2000"
func parseListenAddr(listenAddr string) (string, string) { return "", "" }
func listeners() {
    local := "127.0.0.1:2000"
    net.Listen(parseListenAddr(addr))
    net.Listen("tcp", "0.0.0.0:3000")
    net.Listen("tcp", local)
}
func clients() {
    _ = &http.Client{
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            req.Header = via[len(via)-1].Header.Clone()
            req.Header.Add("Cookie", "a=b")
            req.Header.Set("X-Trace-ID", "123")
            return nil
        },
    }
}
""",
                }
            ]
        )

        bind_all = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.bind-all-interfaces"
        ]
        redirects = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.redirect-sensitive-header"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in bind_all), [11, 12])
        self.assertEqual(sorted(item["sink"]["line"] for item in redirects), [18, 19])

    def test_reports_hardcoded_secret_comparisons(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "secret.go",
                    "content": """
package sample
func run(password string, p string) {
    if password == "f62e5bcda4fae4f82370da0c6f20697b8f8447ef" {}
    if "f62e5bcda4fae4f82370da0c6f20697b8f8447ef" != password {}
    if p != "f62e5bcda4fae4f82370da0c6f20697b8f8447ef" {}
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.hardcoded-secret-comparison"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [4, 5])

    def test_reports_ssh_public_key_callback_that_stores_key_and_allows(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "ssh.go",
                    "content": """
package sample
type PublicKey interface{ Marshal() []byte }
type ConnMetadata interface{ User() string }
type Permissions struct{ Extensions map[string]string }
type ServerConfig struct {
    PublicKeyCallback func(ConnMetadata, PublicKey) (*Permissions, error)
}
var lastKey PublicKey
func bad() {
    config := &ServerConfig{}
    config.PublicKeyCallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
        lastKey = key
        return &Permissions{}, nil
    }
    _ = config
}
func okExtension() {
    config := &ServerConfig{}
    config.PublicKeyCallback = func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
        return &Permissions{Extensions: map[string]string{"pubkey": string(key.Marshal())}}, nil
    }
    _ = config
}
func okFunction(conn ConnMetadata, key PublicKey) (*Permissions, error) {
    return &Permissions{}, nil
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.ssh-public-key-callback-bypass"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("lastKey = key", findings[0]["sink"]["snippet"])

    def test_reports_insecure_writefile_permissions(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "file.go",
                    "content": """
package sample
import (
    "io/ioutil"
    "os"
)
func run(data []byte) {
    ioutil.WriteFile("/tmp/a", data, 0744)
    os.WriteFile("/tmp/b", data, os.ModePerm)
    os.WriteFile("/tmp/c", data, 0600)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.insecure-writefile-permission"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [8, 9])

    def test_reports_dangerous_command_execution_dataflow(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "exec.go",
                    "content": """
package sample
import (
    "context"
    "os/exec"
)
func runCommand(userInput string, s string, ctx context.Context) {
    cmdPath, _ := userInput
    _ = &exec.Cmd{Path: cmdPath, Args: []string{"foo", "bar"}}
    _ = &exec.Cmd{Path: "/bin/echo", Args: []string{userInput, "bar"}}
    _ = exec.Command("bash", "-c", userInput)
    _ = exec.Command("/usr/bin/env", "bash", "-c", s)
    _ = exec.CommandContext(ctx, "/bin/env", "bash", "-c", s)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.dangerous-command-execution"
        ]
        self.assertEqual(sorted(item["sink"]["line"] for item in findings), [9, 10, 11, 12, 13])

    def test_accepts_fixed_command_execution(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "exec.go",
                    "content": """
package sample
import "os/exec"
func ok(userInput string) {
    goExec, _ := exec.LookPath("go")
    _ = exec.Command(goExec, "version")
    _ = &exec.Cmd{Path: goExec, Args: []string{goExec, "version"}}
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.dangerous-command-execution",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_otto_run_from_request_form(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "otto.go",
                    "content": """
package sample
import (
    "net/http"
    "github.com/robertkrimen/otto"
)
func run(w http.ResponseWriter, r *http.Request) {
    script := r.Form.Get("script")
    vm := otto.New()
    _ = vm.Run(script)
}
func ok() {
    vm := otto.New()
    _ = vm.Run(`console.log("ok")`)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.dangerous-script-execution"
        ]
        self.assertEqual([item["sink"]["line"] for item in findings], [10])

    def test_reports_text_template_response_with_request_data(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "template.go",
                    "content": """
package sample
import (
    "net/http"
    "text/template"
)
var tmpl = template.Must(template.New("").Parse(`{{define "greeting"}}Hello {{.}}{{end}}`))
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    _ = tmpl.ExecuteTemplate(w, "greeting", name)
}
""",
                }
            ]
        )

        self.assertIn(
            "secflow.go.semantic.text-template-response-execution",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_accepts_sanitized_or_non_http_text_template_execution(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "template.go",
                    "content": """
package sample
import (
    "html"
    "net/http"
    "os"
    "text/template"
)
var tmpl = template.Must(template.New("page").Parse(`<h1>Hello {{.}}</h1>`))
func handler(w http.ResponseWriter, r *http.Request) {
    safe := html.EscapeString(r.FormValue("name"))
    _ = tmpl.Execute(w, safe)
}
func cli() {
    local := template.Must(template.New("page").Parse(`Hello {{.}}`))
    _ = local.Execute(os.Stdout, "World")
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.text-template-response-execution",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_sensitive_struct_serialization(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "config.go",
                    "content": """
package sample
import "encoding/json"
type Config struct {
    Username string
    Password string
    PublicValue string `json:"api_key"`
}
func encode() {
    _, _ = json.Marshal(Config{})
}
""",
                }
            ]
        )

        self.assertIn(
            "secflow.go.semantic.sensitive-data-serialization",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_sensitive_name_in_multi_field_declaration(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "config.go",
                    "content": """
package sample
import "encoding/json"
type Config struct {
    Safe, Password string
}
func encode() {
    _, _ = json.Marshal(Config{})
}
""",
                }
            ]
        )

        self.assertIn(
            "secflow.go.semantic.sensitive-data-serialization",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_accepts_ignored_or_custom_serialized_sensitive_fields(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "config.go",
                    "content": """
package sample
import "encoding/json"
type Ignored struct {
    Password string `json:"-" yaml:"-"`
}
type Custom struct {
    Secret string
}
type Limits struct {
    MaxTokens int
}
func (Custom) MarshalJSON() ([]byte, error) {
    return json.Marshal(struct{ Name string }{Name: "public"})
}
func encode() {
    _, _ = json.Marshal(Ignored{})
    _, _ = json.Marshal(Custom{})
    _, _ = json.Marshal(Limits{})
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.sensitive-data-serialization",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_proven_integer_and_slice_overflow(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "bounds.go",
                    "content": """
package sample
import "math"
func run() {
    var value uint32 = math.MaxUint32
    narrowed := int32(value)
    data := make([]byte, 0)
    _ = data[:3]
    _ = narrowed
}
""",
                }
            ]
        )
        rules = {item["rule_id"] for item in result["findings"]}

        self.assertIn("secflow.go.semantic.integer-conversion-overflow", rules)
        self.assertIn("secflow.go.semantic.static-slice-out-of-bounds", rules)

    def test_reports_unchecked_range_and_parse_signedness_narrowing(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "integer.go",
                    "content": """
package sample
import "strconv"
func convert(values []int, raw string) {
    for _, value := range values {
        _ = uint8(value)
    }
    parsed, _ := strconv.ParseInt(raw, 10, 8)
    _ = uint8(parsed)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.integer-conversion-overflow"
        ]
        self.assertEqual(len(findings), 2)

    def test_accepts_parse_range_and_explicitly_guarded_narrowing(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "integer.go",
                    "content": """
package sample
import "strconv"
func convert(value int, raw string) {
    parsed, _ := strconv.ParseUint(raw, 10, 8)
    _ = uint8(parsed)
    if value < 0 || value > 255 {
        return
    }
    _ = uint8(value)
}
""",
                }
            ]
        )

        self.assertFalse(result["findings"])

    def test_ignores_integer_conversion_syntax_inside_comments_and_literals(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "integer.go",
                    "content": r'''
package sample
func convert(value int) {
    // uint8(value)
    /* uint16(value) */
    _ = "uint32(value)"
    _ = `uint64(value)`
    _ = 'x'
    if value < 0 || value > 255 {
        return
    }
    _ = uint8(value)
}
''',
                }
            ]
        )

        self.assertFalse(result["findings"])

    def test_accepts_parenthesized_expression_guards_and_signed_byte_compatibility(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "integer.go",
                    "content": """
package sample
func convert(x int, y uint16, v int64) {
    if (x + 10) > 0 && (x + 10) < 100 {
        _ = uint16(x + 10)
    }
    if (y >> 4) < 10 {
        _ = uint8(y >> 4)
    }
    if v < -128 || v > 255 {
        return
    }
    _ = byte(v)
}
""",
                }
            ]
        )

        self.assertFalse(result["findings"])

    def test_accepts_builtin_bounds_unsigned_remainder_and_commutative_add_guard(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "integer.go",
                    "content": """
package sample
import "math"
func convert(items []string, unsigned uint, x int) {
    capacity := cap(items)
    if capacity > math.MaxUint32 {
        return
    }
    _ = uint32(capacity)
    _ = uint8(unsigned % 10)
    if 10 + x < 30 && x > 0 {
        _ = uint8(x)
    }
}
""",
                }
            ]
        )

        self.assertFalse(result["findings"])

    def test_reports_interprocedural_and_builder_sql_taint(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "sql.go",
                    "content": """
package sample
import (
    "database/sql"
    "net/http"
    "os"
    "strings"
)
func input(r *http.Request) string { return r.FormValue("id") }
func forwarded(r *http.Request) string { return input(r) }
func handler(db *sql.DB, r *http.Request) {
    value := forwarded(r)
    query := "SELECT * FROM users WHERE id='" + value + "'"
    db.Query(query)
}
func builder(db *sql.DB) {
    var values strings.Builder
    for _, value := range os.Args {
        values.WriteString(value)
    }
    query := "SELECT * FROM users WHERE id IN (" + values.String() + ")"
    db.Query(query)
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.interprocedural-sql-injection"
        ]
        self.assertEqual(len(findings), 2)

    def test_interprocedural_sql_taint_requires_dynamic_sql_sink(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "sql.go",
                    "content": """
package sample
import (
    "database/sql"
    "net/http"
    "strconv"
)
func input(r *http.Request) string { return r.FormValue("id") }
func handler(db *sql.DB, r *http.Request) {
    raw := input(r)
    id, _ := strconv.Atoi(raw)
    db.Query("SELECT * FROM users WHERE id = ?", id)
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.interprocedural-sql-injection",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_propagates_arithmetic_and_inverted_division_ranges_before_narrowing(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "integer.go",
                    "content": """
package sample
func conversions(x int, values []int) uint16 {
    if x >= 0 && x < 30 {
        _ = uint8(x * 10)
    }
    if x > 0 && 10000 / x < 5 {
        return uint16(x)
    }
    for _, value := range values {
        if value >= 0 {
            _ = uint8(value)
        }
    }
    return 0
}
""",
                }
            ]
        )

        findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.integer-conversion-overflow"
        ]
        self.assertEqual(len(findings), 3)

    def test_does_not_report_static_safe_bounds(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "bounds.go",
                    "content": """
package sample
func run() {
    data := make([]byte, 2, 4)
    _ = data[1]
    _ = data[:4]
}
""",
                }
            ]
        )

        self.assertFalse(result["findings"])

    def test_reports_alias_loop_and_three_index_bounds(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "bounds.go",
                    "content": """
package sample
func run() {
    data := make([]byte, 0, 4)
    alias := data[:2]
    _ = alias[:10]
    values := make([]int, 16)
    for i := 10; i < 17; i++ {
        values[i] = i
    }
    var fixed [10]int
    maximum := 11
    _ = fixed[:5:maximum]
}
""",
                }
            ]
        )

        findings = [item for item in result["findings"] if "out-of-bounds" in item["rule_id"]]
        self.assertGreaterEqual(len(findings), 3)

    def test_respects_index_specific_length_guards(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "bounds.go",
                    "content": """
package sample
func run() {
    data := make([]byte, 0)
    if len(data) > 0 {
        _ = data[0]
        _ = data[2]
    }
}
""",
                }
            ]
        )

        bounds = [item for item in result["findings"] if "out-of-bounds" in item["rule_id"]]
        self.assertEqual(len(bounds), 1)

    def test_invalidates_bounds_after_append_or_pointer_escape(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "bounds.go",
                    "content": """
package sample
import "encoding/json"
func run(raw []byte) {
    appended := make([]int, 0)
    appended = append(appended, 1, 2)
    _ = appended[1]

    decoded := make([]int, 0)
    _ = json.Unmarshal(raw, &decoded)
    _ = decoded[2]
}
""",
                }
            ]
        )

        self.assertFalse(result["findings"])

    def test_handles_reverse_guard_else_and_len_loop_bounds(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "bounds.go",
                    "content": """
package sample
func run() {
    safe := make([]byte, 4)
    if 5 < len(safe) {
        _ = safe[4]
    }
    data := make([]byte, 0)
    if len(data) > 4 {
        _ = data[3]
    } else {
        _ = data[2]
    }
    var fixed [20]int
    for i := 1; i <= len(fixed); i++ {
        fixed[i] = i
    }
}
""",
                }
            ]
        )

        bounds = [item for item in result["findings"] if "out-of-bounds" in item["rule_id"]]
        self.assertEqual(len(bounds), 2)

    def test_reports_fixed_nonce_through_one_call(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "crypto.go",
                    "content": """
package sample
import "crypto/cipher"
func encrypt(block cipher.Block, nonce []byte) {
    _ = cipher.NewCTR(block, nonce)
}
func run(block cipher.Block) {
    nonce := make([]byte, 16)
    encrypt(block, nonce)
}
""",
                }
            ]
        )

        self.assertIn(
            "secflow.go.semantic.fixed-crypto-nonce",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_accepts_randomized_nonce(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "crypto.go",
                    "content": """
package sample
import (
    "crypto/cipher"
    "crypto/rand"
)
func run(block cipher.Block) {
    nonce := make([]byte, 16)
    _, _ = rand.Read(nonce)
    _ = cipher.NewCTR(block, nonce)
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.fixed-crypto-nonce",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_accepts_fixed_nonce_for_decryption_and_nosec(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "crypto.go",
                    "content": """
package sample
func decrypt(gcm interface{ Open([]byte, []byte, []byte, []byte) ([]byte, error) }) {
    nonce := []byte("fixed-nonce")
    _, _ = gcm.Open(nil, nonce, nil, nil)
}
func encrypt(gcm interface{ Seal([]byte, []byte, []byte, []byte) []byte }) {
    _ = gcm.Seal(nil, func() []byte { return []byte("fixed-nonce") }(), nil, nil) // #nosec G407
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.fixed-crypto-nonce",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_accepts_random_write_outside_nonce_slice(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "crypto.go",
                    "content": """
package sample
import (
    "crypto/cipher"
    "crypto/rand"
)
func run(block cipher.Block, index int) {
    nonce := make([]byte, 128)
    _, _ = rand.Read(nonce)
    if index >= 16 && index < 128 {
        nonce[index] = 0
    }
    _ = cipher.NewCTR(block, nonce[:16])
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.fixed-crypto-nonce",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_accepts_nonce_randomized_by_helper_or_callback(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "crypto.go",
                    "content": """
package sample
import (
    "crypto/cipher"
    "crypto/rand"
)
func fill(b []byte) (int, error) {
    return rand.Read(b)
}
func helper(block cipher.Block) {
    nonce := make([]byte, 16)
    fill(nonce)
    _ = cipher.NewCTR(block, nonce)
}
func callback(block cipher.Block, init func([]byte)) {
    nonce := make([]byte, 16)
    init(nonce)
    _ = cipher.NewCTR(block, nonce)
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.fixed-crypto-nonce",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_fixed_nonce_alias_write_after_randomization(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "crypto.go",
                    "content": """
package sample
import (
    "crypto/cipher"
    "crypto/rand"
)
func run(block cipher.Block) {
    nonce := make([]byte, 16)
    rand.Read(nonce)
    alias := nonce
    alias[0] = 0
    _ = cipher.NewCTR(block, nonce)
}
""",
                }
            ]
        )

        self.assertIn(
            "secflow.go.semantic.fixed-crypto-nonce",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_accepts_fixed_nonce_write_overwritten_by_later_random_read(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "crypto.go",
                    "content": """
package sample
import (
    "crypto/cipher"
    "crypto/rand"
)
func run(block cipher.Block) {
    nonce := make([]byte, 16)
    rand.Read(nonce[6:12])
    nonce[6] = 0
    rand.Read(nonce[0:7])
    nonce[10] = 0
    rand.Read(nonce[10:16])
    _ = cipher.NewCTR(block, nonce)
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.fixed-crypto-nonce",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_jwt_parse_unverified_weak_rsa_and_xxe(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "security.go",
                    "content": """
package sample
import (
    "crypto/rand"
    "crypto/rsa"
    "fmt"
    "github.com/dgrijalva/jwt-go"
    "github.com/lestrrat-go/libxml2/parser"
)
func jwtBad(tokenString string) {
    _, _, _ = new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
}
func rsaBad() {
    _, _ = rsa.GenerateKey(rand.Reader, 1024)
    _, _ = rsa.GenerateKey(rand.Reader, 2048)
}
func xxeBad(raw string) {
    p := parser.New(parser.XMLParseNoEnt)
    doc, _ := p.ParseString(raw)
    fmt.Println(doc)
}
""",
                }
            ]
        )

        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertIn("secflow.go.semantic.jwt-parse-unverified", rule_ids)
        self.assertIn("secflow.go.semantic.weak-rsa-key", rule_ids)
        self.assertIn("secflow.go.semantic.xxe-external-entities", rule_ids)
        self.assertEqual(
            1,
            sum(1 for item in result["findings"] if item["rule_id"] == "secflow.go.semantic.weak-rsa-key"),
        )

    def test_reports_websocket_missing_origin_only_without_local_override(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "ws.go",
                    "content": """
package sample
import (
    "net/http"
    "github.com/gorilla/websocket"
)
var checked = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
var unchecked = websocket.Upgrader{ReadBufferSize: 1024}
func ok(w http.ResponseWriter, r *http.Request) {
    _, _ = checked.Upgrade(w, r, nil)
}
func okAssigned(w http.ResponseWriter, r *http.Request) {
    unchecked.CheckOrigin = func(r *http.Request) bool { return true }
    _, _ = unchecked.Upgrade(w, r, nil)
}
func bad(w http.ResponseWriter, r *http.Request) {
    _, _ = unchecked.Upgrade(w, r, nil)
}
""",
                }
            ]
        )

        websocket_findings = [
            item
            for item in result["findings"]
            if item["rule_id"] == "secflow.go.semantic.websocket-missing-origin-check"
        ]
        self.assertEqual(1, len(websocket_findings))
        self.assertIn("unchecked.Upgrade", websocket_findings[0]["evidence"])

    def test_reports_responsewriter_and_template_xss(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "xss.go",
                    "content": """
package sample
import (
    "fmt"
    "html/template"
    "net/http"
)
func formatted(r *http.Request) template.HTML {
    customerID := r.URL.Query().Get("id")
    tmpl, _ := fmt.Printf("<html><body>%s</body></html>", customerID)
    return template.HTML(tmpl)
}
func handler(w http.ResponseWriter, r *http.Request) {
    tok := r.FormValue("token")
    fmt.Fprintf(w, "Invalid token: %q", tok)
    fmt.Fprintf(w, "<a href=\\"%s\\">%s</a>", r.RequestURI, tok)
    w.Write([]byte(fmt.Sprintf("<b>%s</b>", tok)))
}
func helper(rw *http.ResponseWriter, body string) {
    (*rw).Write([]byte(body))
}
func ok(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "<pre>\\n")
    w.Write([]byte("alive"))
}
""",
                }
            ]
        )

        rules = [item["rule_id"] for item in result["findings"]]
        self.assertIn("secflow.go.semantic.formatted-template-xss", rules)
        self.assertGreaterEqual(rules.count("secflow.go.semantic.responsewriter-xss"), 4)

    def test_reports_http_protocol_boundary_and_pprof_findings(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "http.go",
                    "content": """
package sample
import (
    "net"
    "net/http"
    "net/smtp"
    "unsafe"
    _ "net/http/pprof"
)
func pprofBad() {
    http.ListenAndServe(":8080", nil)
}
func pprofOk() {
    http.ListenAndServe("127.0.0.1:8080", nil)
}
func smuggling(w http.ResponseWriter, r *http.Request) {
    h := w.Header()
    h.Set("Transfer-Encoding", "chunked")
    h.Set("Content-Length", "100")
}
func unbounded() {
    l, _ := net.Listen("tcp", ":8081")
    _ = http.Serve(l, nil)
}
func mail(r *http.Request) {
    from := r.FormValue("from")
    to := []string{r.FormValue("to")}
    _ = smtp.SendMail("127.0.0.1:25", nil, from, to, []byte("Subject: Hi\\r\\n\\r\\nbody"))
}
func unsafeUse() {
    chars := [...]byte{1, 2}
    _ = unsafe.String(&chars[0], len(chars))
}
""",
                }
            ]
        )

        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertIn("secflow.go.semantic.pprof-debug-exposure", rule_ids)
        self.assertIn("secflow.go.semantic.http-smuggling-conflicting-headers", rule_ids)
        self.assertIn("secflow.go.semantic.unbounded-http-serve", rule_ids)
        self.assertIn("secflow.go.semantic.smtp-header-injection", rule_ids)
        self.assertIn("secflow.go.semantic.unsafe-pointer-conversion", rule_ids)
        self.assertEqual(
            1,
            sum(1 for item in result["findings"] if item["rule_id"] == "secflow.go.semantic.pprof-debug-exposure"),
        )

    def test_reports_cross_origin_bypass_without_flagging_literal_trusted_template_types(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "misc.go",
                    "content": """
package sample
import (
    "html/template"
    "net/http"
)
func setup() {
    var cop http.CrossOriginProtection
    cop.AddInsecureBypassPattern("/")
}
func templateTypes() {
    var js template.JS = "{foo: 'bar'}"
    var jsstr template.JSStr = "setTimeout('alert()')"
    _ = js
    _ = jsstr
}
""",
                }
            ]
        )

        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertIn("secflow.go.semantic.cross-origin-bypass", rule_ids)
        self.assertNotIn("secflow.go.semantic.trusted-template-type", rule_ids)

    def test_reports_reflect_proxy_zip_shared_url_and_tainted_command_argument(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "advanced.go",
                    "content": """
package sample
import (
    "archive/zip"
    "io"
    "net/http"
    "net/http/httputil"
    "net/url"
    "os"
    "os/exec"
    "reflect"
)
var redirectURL, _ = url.Parse("https://example.com")
func unzip() {
    r, _ := zip.OpenReader("tmp.zip")
    for _, f := range r.File {
        rc, _ := f.Open()
        _, _ = io.Copy(os.Stdout, rc)
    }
}
func proxy(target *url.URL) {
    p := httputil.NewSingleHostReverseProxy(target)
    p.Director = func(req *http.Request) {}
}
func shared(w http.ResponseWriter, r *http.Request) {
    u := redirectURL
    u.RawQuery = "token=1"
}
func refl(name string, typ reflect.Type, v reflect.Value) {
    _ = reflect.MakeFunc(typ, func(args []reflect.Value) []reflect.Value { return nil })
    _ = v.MethodByName(name)
    _ = v.FieldByName("constant")
}
func cmd(r *http.Request) {
    filename := r.URL.Query().Get("file")
    _ = exec.Command("cat", filename)
}
func safe() {
    _ = exec.Command("ls", "-la")
}
""",
                }
            ]
        )

        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertIn("secflow.go.semantic.zip-unbounded-copy", rule_ids)
        self.assertIn("secflow.go.semantic.reverseproxy-director-override", rule_ids)
        self.assertIn("secflow.go.semantic.shared-url-struct-mutation", rule_ids)
        self.assertIn("secflow.go.semantic.reflect-makefunc", rule_ids)
        self.assertIn("secflow.go.semantic.reflect-by-name-dynamic", rule_ids)
        self.assertIn("secflow.go.semantic.dangerous-command-execution", rule_ids)
        self.assertEqual(
            1,
            sum(1 for item in result["findings"] if item["rule_id"] == "secflow.go.semantic.reflect-by-name-dynamic"),
        )

    def test_reports_project_global_sql_and_session_identity_overwrite(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "case/source-0.go",
                    "content": """
package sample
import "os"
var query string = "SELECT * FROM foo WHERE name = "
func init() {
    query += os.Args[1]
}
""",
                },
                {
                    "file_name": "case/source-1.go",
                    "content": """
package sample
import "database/sql"
func main() {
    db, _ := sql.Open("sqlite3", ":memory:")
    _, _ = db.Query(query)
}
""",
                },
                {
                    "file_name": "other/source-0.go",
                    "content": """
package sample
import "database/sql"
var query string = "SELECT * FROM foo WHERE id = "
func main() {
    db, _ := sql.Open("sqlite3", ":memory:")
    _, _ = db.Query(query + "42")
}
""",
                },
                {
                    "file_name": "session.go",
                    "content": """
package sample
import (
    "net/http"
    "github.com/gorilla/sessions"
)
var store = sessions.NewCookieStore([]byte("secret"))
func ValidateUser(user_id int) bool { return true }
func bad(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "sid")
    var user_id int = session.Values["user_id"].(int)
    if !ValidateUser(user_id) {
        return
    }
    user_id = r.query.params.user_id
}
func ok(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "sid")
    user_id := session.Values["user_id"]
    if !ValidateUser(user_id) {
        return
    }
    user_id = augment(user_id, "ok")
}
""",
                },
            ]
        )

        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertIn("secflow.go.semantic.project-global-sql-injection", rule_ids)
        self.assertIn("secflow.go.semantic.session-identity-overwrite", rule_ids)
        self.assertEqual(
            1,
            sum(1 for item in result["findings"] if item["rule_id"] == "secflow.go.semantic.project-global-sql-injection"),
        )
        self.assertEqual(
            1,
            sum(1 for item in result["findings"] if item["rule_id"] == "secflow.go.semantic.session-identity-overwrite"),
        )

    def test_reports_external_url_audit_and_syscall_startprocess(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "ssrf_exec.go",
                    "content": """
package sample
import (
    "net/http"
    "syscall"
)
var Url string
func get(url string) {
    _, _ = http.Get(url)
}
func exported() {
    _, _ = http.Get(Url)
}
func safe() {
    local := "http://127.0.0.1"
    _, _ = http.Get(local)
}
func run(command string) {
    _, _, _ = syscall.StartProcess(command, []string{}, nil)
}
func safeRun() {
    _, _, _ = syscall.StartProcess("/bin/cat", []string{}, nil)
}
""",
                }
            ]
        )

        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertIn("secflow.go.semantic.external-url-http-client", rule_ids)
        self.assertIn("secflow.go.semantic.syscall-startprocess-variable", rule_ids)
        self.assertEqual(
            2,
            sum(1 for item in result["findings"] if item["rule_id"] == "secflow.go.semantic.external-url-http-client"),
        )
        self.assertEqual(
            1,
            sum(1 for item in result["findings"] if item["rule_id"] == "secflow.go.semantic.syscall-startprocess-variable"),
        )


if __name__ == "__main__":
    unittest.main()
