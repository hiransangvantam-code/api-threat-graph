// One service of a test company, Go version (standard library only).
//
// Same behaviour as companies/runtime/python/service.py (read that file's header):
// SERVICE=<name> picks the role from company.json: the gateway, the auth service, or
// a backend with the routes listed for it.
//
// Routing uses the Go 1.22 net/http patterns ("GET /wallets/{wallet_id}"). Spans are
// sent to OTEL_EXPORTER_OTLP_ENDPOINT as OTLP/HTTP JSON by the small exporter below,
// with the current semantic-convention attribute names.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------- company.json
type Call struct {
	Service     string `json:"service"`
	Port        int    `json:"port"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	ForwardAuth bool   `json:"forward_auth"`
	Body        any    `json:"body"`
}

type External struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

type Route struct {
	Method      string     `json:"method"`
	Path        string     `json:"path"`
	Auth        string     `json:"auth"`
	Owner       string     `json:"owner"`
	OwnerCheck  *bool      `json:"owner_check"`
	ErrorsEvery int        `json:"errors_every"`
	Status      int        `json:"status"`
	Calls       []Call     `json:"calls"`
	External    []External `json:"external"`
	Returns     any        `json:"returns"`
}

type Spec struct {
	Path string `json:"path"`
	File string `json:"file"`
	Type string `json:"type"`
}

type Service struct {
	Port   int     `json:"port"`
	Traced *bool   `json:"traced"`
	Spec   *Spec   `json:"spec"`
	Routes []Route `json:"routes"`
}

type GwRoute struct {
	Prefix      string `json:"prefix"`
	Service     string `json:"service"`
	Port        int    `json:"port"`
	From        string `json:"from"`
	To          string `json:"to"`
	Auth        bool   `json:"auth"`
	LimitPerMin int    `json:"limit_per_min"`
}

type Company struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Credential  string `json:"credential"`
	AuthService struct {
		Name string `json:"name"`
		Port int    `json:"port"`
	} `json:"auth_service"`
	Gateway struct {
		Name   string    `json:"name"`
		Port   int       `json:"port"`
		Traced *bool     `json:"traced"`
		Routes []GwRoute `json:"routes"`
	} `json:"gateway"`
	Services map[string]Service `json:"services"`
}

var (
	cfg     Company
	name    string
	port    int
	traced  bool
	otlpURL string
	mesh    *http.Client
	direct  = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	userRE  = regexp.MustCompile(`^(c([1-9]|1[0-9]|20)|staff[1-3]|p[1-3])$`)
	paramRE = regexp.MustCompile(`{([^}]+)}`)
)

// ---------------------------------------------------------------- tracing (OTLP/HTTP JSON)
type attr struct {
	Key   string         `json:"key"`
	Value map[string]any `json:"value"`
}

type span struct {
	TraceID string         `json:"traceId"`
	SpanID  string         `json:"spanId"`
	Parent  string         `json:"parentSpanId,omitempty"`
	Name    string         `json:"name"`
	Kind    int            `json:"kind"`
	Start   string         `json:"startTimeUnixNano"`
	End     string         `json:"endTimeUnixNano"`
	Attrs   []attr         `json:"attributes"`
	Status  map[string]int `json:"status"`
}

var (
	spanMu  sync.Mutex
	pending []*span
)

func newID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func startSpan(spanName string, kind int, traceID, parent string) *span {
	if !traced {
		return nil
	}
	if traceID == "" {
		traceID, parent = newID(16), ""
	}
	return &span{TraceID: traceID, SpanID: newID(8), Parent: parent, Name: spanName, Kind: kind,
		Start: strconv.FormatInt(time.Now().UnixNano(), 10), Status: map[string]int{"code": 0}}
}

func (s *span) set(k string, v any) {
	if s == nil {
		return
	}
	if i, ok := v.(int); ok {
		s.Attrs = append(s.Attrs, attr{k, map[string]any{"intValue": strconv.Itoa(i)}})
		return
	}
	s.Attrs = append(s.Attrs, attr{k, map[string]any{"stringValue": fmt.Sprint(v)}})
}

func (s *span) finish(failed bool) {
	if s == nil {
		return
	}
	s.End = strconv.FormatInt(time.Now().UnixNano(), 10)
	if failed {
		s.Status = map[string]int{"code": 2}
	}
	spanMu.Lock()
	pending = append(pending, s)
	spanMu.Unlock()
}

func (s *span) traceparent() string {
	if s == nil {
		return ""
	}
	return "00-" + s.TraceID + "-" + s.SpanID + "-01"
}

func exportLoop() {
	for {
		time.Sleep(500 * time.Millisecond)
		spanMu.Lock()
		batch := pending
		pending = nil
		spanMu.Unlock()
		if len(batch) == 0 {
			continue
		}
		res := []attr{{"service.name", map[string]any{"stringValue": name}},
			{"service.namespace", map[string]any{"stringValue": cfg.ID}}}
		doc := map[string]any{"resourceSpans": []any{map[string]any{
			"resource":   map[string]any{"attributes": res},
			"scopeSpans": []any{map[string]any{"scope": map[string]any{"name": cfg.ID + "-runtime-go"}, "spans": batch}},
		}}}
		b, _ := json.Marshal(doc)
		r, err := direct.Post(otlpURL, "application/json", bytes.NewReader(b))
		if err == nil {
			_, _ = io.Copy(io.Discard, r.Body)
			r.Body.Close()
		}
	}
}

// incoming W3C traceparent -> (trace id, parent span id)
func parentOf(r *http.Request) (string, string) {
	p := strings.Split(r.Header.Get("traceparent"), "-")
	if !traced || len(p) != 4 || len(p[1]) != 32 || len(p[2]) != 16 {
		return "", ""
	}
	return p[1], p[2]
}

func endServer(s *span, r *http.Request, route string, status int) {
	s.set("http.request.method", r.Method)
	s.set("http.route", route)
	s.set("url.path", r.URL.Path)
	s.set("http.response.status_code", status)
	s.set("user_agent.original", r.UserAgent())
	s.finish(status >= 500)
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

// a traced outgoing call; parent is the current server span
func call(parent *span, client *http.Client, method, target, peer string, headers map[string]string, body []byte) resp {
	u, _ := url.Parse(target)
	var cs *span
	if parent != nil {
		cs = startSpan(method+" "+peer, 3, parent.TraceID, parent.SpanID)
	}
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return resp{status: 502}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if len(body) > 0 && req.Header.Get("content-type") == "" {
		req.Header.Set("content-type", "application/json")
	}
	if cs != nil {
		req.Header.Set("traceparent", cs.traceparent())
		portNum, _ := strconv.Atoi(u.Port())
		cs.set("http.request.method", method)
		cs.set("peer.service", peer)
		cs.set("server.address", u.Hostname())
		cs.set("server.port", portNum)
		cs.set("url.full", u.Scheme+"://"+u.Host+u.Path)
	}
	r, err := client.Do(req)
	if err != nil {
		cs.finish(true)
		return resp{status: 502}
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	cs.set("http.response.status_code", r.StatusCode)
	cs.finish(r.StatusCode >= 500)
	return resp{r.StatusCode, r.Header, b}
}

// ---------------------------------------------------------------- helpers shared with the other runtimes
func roleOf(u string) string {
	switch {
	case strings.HasPrefix(u, "staff"):
		return "staff"
	case strings.HasPrefix(u, "p"):
		return "partner"
	}
	return "customer"
}

func ownerOf(v string) string {
	digits := regexp.MustCompile(`\D`).ReplaceAllString(v, "")
	if digits == "" {
		return "c1"
	}
	n, _ := strconv.Atoi(digits)
	return "c" + strconv.Itoa(n%20+1)
}

func render(t any, params map[string]string, owner, user string, n int) any {
	switch x := t.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, v := range x {
			out[k] = render(v, params, owner, user, n)
		}
		return out
	case []any:
		if len(x) == 0 {
			return []any{}
		}
		return []any{render(x[0], params, owner, user, n*10), render(x[0], params, owner, user, n*10+1)}
	case string:
		if !strings.HasPrefix(x, "$") {
			return x
		}
		key := x[1:]
		switch key {
		case "owner":
			return owner
		case "user":
			if user == "" {
				return "anonymous"
			}
			return user
		case "n":
			return n
		}
		if v, ok := params[key]; ok {
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
			return v
		}
	}
	return t
}

func fill(path string, params map[string]string) string {
	return paramRE.ReplaceAllStringFunc(path, func(m string) string {
		if v, ok := params[m[1:len(m)-1]]; ok {
			return v
		}
		return "1"
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return h[7:]
	}
	return ""
}

// ---------------------------------------------------------------- the auth service's own endpoints
var (
	sessMu   sync.Mutex
	sessions = map[string][2]string{}
)

func login(w http.ResponseWriter, r *http.Request) {
	tid, pid := parentOf(r)
	s := startSpan("POST /auth/session", 2, tid, pid)
	var in struct {
		User string `json:"user"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	status := 401
	if !userRE.MatchString(in.User) {
		writeJSON(w, 401, map[string]any{"error": "unknown user"})
	} else {
		token := newID(16)
		sessMu.Lock()
		sessions[token] = [2]string{in.User, roleOf(in.User)}
		sessMu.Unlock()
		status = 200
		if cfg.Credential == "cookie" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
			writeJSON(w, 200, map[string]any{"user": in.User, "role": roleOf(in.User)})
		} else {
			writeJSON(w, 200, map[string]any{"user": in.User, "role": roleOf(in.User), "access_token": token, "token_type": "Bearer"})
		}
	}
	endServer(s, r, "/auth/session", status)
}

func introspect(w http.ResponseWriter, r *http.Request) {
	tid, pid := parentOf(r)
	s := startSpan("GET /auth/introspect", 2, tid, pid)
	sessMu.Lock()
	who, ok := sessions[bearer(r)]
	sessMu.Unlock()
	if ok {
		writeJSON(w, 200, map[string]any{"user": who[0], "role": who[1], "active": true})
		endServer(s, r, "/auth/introspect", 200)
		return
	}
	writeJSON(w, 401, map[string]any{"active": false})
	endServer(s, r, "/auth/introspect", 401)
}

// ---------------------------------------------------------------- a backend route
var (
	countMu sync.Mutex
	counts  = map[string]int{}
)

func serve(r *http.Request, rt Route, s *span) (int, any) {
	countMu.Lock()
	counts[rt.Method+" "+rt.Path]++
	n := counts[rt.Method+" "+rt.Path]
	countMu.Unlock()
	params := map[string]string{}
	for _, m := range paramRE.FindAllStringSubmatch(rt.Path, -1) {
		params[m[1]] = r.PathValue(m[1])
	}
	if rt.ErrorsEvery > 0 && n%rt.ErrorsEvery == 0 {
		return 500, map[string]any{"error": "internal error"}
	}
	user, role := r.Header.Get("x-user-id"), r.Header.Get("x-user-role")
	if rt.Auth != "none" {
		if user == "" {
			return 401, map[string]any{"error": "authentication required"}
		}
		if (rt.Auth == "admin" && role != "staff") || (rt.Auth == "partner" && role != "partner") {
			return 403, map[string]any{"error": "forbidden"}
		}
	}
	owner := user
	if owner == "" {
		owner = "c1"
	}
	if rt.Owner != "" {
		owner = ownerOf(params[rt.Owner])
		if (rt.OwnerCheck == nil || *rt.OwnerCheck) && role == "customer" && owner != user {
			return 403, map[string]any{"error": "not your object"}
		}
	}
	fwd := map[string]string{}
	for _, k := range []string{"authorization", "cookie", "x-api-key", "x-user-id", "x-user-role"} {
		if v := r.Header.Get(k); v != "" {
			fwd[k] = v
		}
	}
	for _, c := range rt.Calls {
		h := map[string]string{}
		if c.ForwardAuth {
			h = fwd
		}
		var body []byte
		if c.Body != nil {
			body, _ = json.Marshal(c.Body)
		}
		res := call(s, mesh, c.Method, fmt.Sprintf("http://%s:%d%s", c.Service, c.Port, fill(c.Path, params)), c.Service, h, body)
		if res.status >= 500 {
			return 502, map[string]any{"error": c.Service + " failed"}
		}
	}
	for _, x := range rt.External {
		call(s, direct, x.Method, fmt.Sprintf("http://%s:%d%s", x.Host, x.Port, x.Path), x.Host, nil, nil)
	}
	status := rt.Status
	if status == 0 {
		status = 200
	}
	ret := rt.Returns
	if ret == nil {
		ret = map[string]any{"status": "ok"}
	}
	return status, render(ret, params, owner, user, n)
}

func handler(rt Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid, pid := parentOf(r)
		s := startSpan(rt.Method+" "+rt.Path, 2, tid, pid)
		status, body := serve(r, rt, s)
		writeJSON(w, status, body)
		endServer(s, r, rt.Path, status)
	}
}

// ---------------------------------------------------------------- the gateway
var (
	rateMu  sync.Mutex
	windows = map[string]*[2]int64{}
	identMu sync.Mutex
	idents  = map[string]*[2]string{}
)

func credential(r *http.Request) string {
	if t := bearer(r); t != "" {
		return t
	}
	if t := r.Header.Get("x-api-key"); t != "" {
		return t
	}
	if c, err := r.Cookie("sid"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("access_token")
}

func identify(s *span, token string) *[2]string {
	identMu.Lock()
	who, ok := idents[token]
	identMu.Unlock()
	if ok {
		return who
	}
	res := call(s, mesh, "GET", fmt.Sprintf("http://%s:%d/auth/introspect", cfg.AuthService.Name, cfg.AuthService.Port),
		cfg.AuthService.Name, map[string]string{"authorization": "Bearer " + token}, nil)
	who = nil
	if res.status == 200 {
		var b struct{ User, Role string }
		if json.Unmarshal(res.body, &b) == nil {
			who = &[2]string{b.User, b.Role}
		}
	}
	identMu.Lock()
	idents[token] = who
	identMu.Unlock()
	return who
}

func gateway(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/health" {
		writeJSON(w, 200, map[string]any{"status": "ok"})
		return
	}
	var rt *GwRoute
	for i := range cfg.Gateway.Routes {
		x := &cfg.Gateway.Routes[i]
		if p == x.Prefix || strings.HasPrefix(p, strings.TrimSuffix(x.Prefix, "/")+"/") {
			rt = x
			break
		}
	}
	if rt == nil {
		writeJSON(w, 404, map[string]any{"error": "no route"})
		return
	}
	route := strings.TrimSuffix(rt.Prefix, "/") + "/**"
	tid, pid := parentOf(r)
	s := startSpan(r.Method+" "+route, 2, tid, pid)
	status := forward(w, r, rt, p, s)
	endServer(s, r, route, status)
}

func forward(w http.ResponseWriter, r *http.Request, rt *GwRoute, p string, s *span) int {
	if rt.LimitPerMin > 0 {
		rateMu.Lock()
		win := windows[rt.Prefix]
		if win == nil || time.Now().Unix()-win[0] > 60 {
			win = &[2]int64{time.Now().Unix(), 0}
			windows[rt.Prefix] = win
		}
		win[1]++
		over := win[1] > int64(rt.LimitPerMin)
		rateMu.Unlock()
		if over {
			writeJSON(w, 429, map[string]any{"error": "too many requests"})
			return 429
		}
	}
	var who *[2]string
	if token := credential(r); token != "" {
		who = identify(s, token)
	}
	if rt.Auth && who == nil {
		writeJSON(w, 401, map[string]any{"error": "authentication required"})
		return 401
	}
	headers := map[string]string{}
	for _, k := range []string{"authorization", "cookie", "x-api-key", "content-type", "user-agent", "accept"} {
		if v := r.Header.Get(k); v != "" {
			headers[k] = v
		}
	}
	if who != nil {
		headers["x-user-id"], headers["x-user-role"] = who[0], who[1]
	}
	backend := rt.To + strings.TrimPrefix(p, rt.From)
	if !strings.HasPrefix(backend, "/") {
		backend = "/" + backend
	}
	target := fmt.Sprintf("http://%s:%d%s", rt.Service, rt.Port, backend)
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	body, _ := io.ReadAll(r.Body)
	up := call(s, mesh, r.Method, target, rt.Service, headers, body)
	for _, k := range []string{"content-type", "set-cookie"} {
		if v := up.header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(up.status)
	_, _ = w.Write(up.body)
	return up.status
}

// ---------------------------------------------------------------- main
func main() {
	path := os.Getenv("COMPANY")
	if path == "" {
		path = "/company/company.json"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatal(err)
	}
	name = os.Getenv("SERVICE")
	isGateway := name == cfg.Gateway.Name
	me, known := cfg.Services[name]
	if !isGateway && !known {
		log.Fatalf("service %q is not in %s", name, path)
	}
	port = me.Port
	tr := me.Traced
	if isGateway {
		port, tr = cfg.Gateway.Port, cfg.Gateway.Traced
	}
	if v := os.Getenv("PORT"); v != "" {
		port, _ = strconv.Atoi(v)
	}
	if len(os.Args) > 1 && os.Args[1] == "-health" {
		r, err := direct.Get(fmt.Sprintf("http://localhost:%d/health", port))
		if err != nil || r.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	traced = (tr == nil || *tr) && endpoint != ""
	otlpURL = strings.TrimSuffix(endpoint, "/") + "/v1/traces"
	tp := &http.Transport{Proxy: nil}
	if m := os.Getenv("MESH_PROXY"); m != "" {
		if mu, err := url.Parse(m); err == nil {
			tp.Proxy = http.ProxyURL(mu)
		}
	}
	mesh = &http.Client{Timeout: 10 * time.Second, Transport: tp}
	if traced {
		go exportLoop()
	}

	mux := http.NewServeMux()
	if isGateway {
		mux.HandleFunc("/", gateway)
	} else {
		mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{"status": "ok", "service": name})
		})
		if me.Spec != nil {
			text, err := os.ReadFile("/company/" + me.Spec.File)
			if err != nil {
				log.Fatal(err)
			}
			ct := me.Spec.Type
			mux.HandleFunc("GET "+me.Spec.Path, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", ct)
				_, _ = w.Write(text)
			})
		}
		if name == cfg.AuthService.Name {
			mux.HandleFunc("POST /auth/session", login)
			mux.HandleFunc("GET /auth/introspect", introspect)
		}
		routes := append([]Route(nil), me.Routes...)
		sort.SliceStable(routes, func(i, j int) bool { return strings.Count(routes[i].Path, "{") < strings.Count(routes[j].Path, "{") })
		for _, rt := range routes {
			mux.HandleFunc(rt.Method+" "+rt.Path, handler(rt))
		}
	}
	log.Printf("%s (%s) listening on :%d", name, cfg.Name, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), mux))
}
