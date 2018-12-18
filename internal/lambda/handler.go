// Package httpserver implements an HTTPS server which handles DNS requests
// over HTTPS.
//
// It implements:
//  - Google's DNS over HTTPS using JSON (dns-json), as specified in:
//    https://developers.google.com/speed/public-dns/docs/dns-over-https#api_specification.
//    This is also implemented by Cloudflare's 1.1.1.1, as documented in:
//    https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/.
//  - DNS Queries over HTTPS (DoH), as specified in:
//    https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-12.
package lambda

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/apex/gateway"
	"github.com/prjctgeek/dnss/internal/dnsjson"

	"github.com/miekg/dns"
)

type Server struct {
	Addr     string
	Upstream string
}

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}

func (s *Server) ListenAndServe() {
	/* mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.Resolve)
	mux.HandleFunc("/resolve", s.Resolve)
	*/
	http.HandleFunc("/dns-query", s.Resolve)
	http.HandleFunc("/resolve", s.Resolve)
	http.HandleFunc("/ping", s.Ping)

	log.Printf("Starting gateway.ListenAndServe")
	log.Fatalf("HTTPS exiting: %s", gateway.ListenAndServe(s.Addr, nil))
}

func (s *Server) Ping(w http.ResponseWriter, req *http.Request) {
	// Health check target.
	requestContext, ok := gateway.RequestContext(req.Context())
	if !ok || requestContext.Authorizer["sub"] == nil {
		fmt.Fprintf(w, "Hello World from DNS Over HTTP Lambda %t, %s", ok, requestContext.ResourcePath)
		return
	}
}

// Resolve implements the HTTP handler for incoming DNS resolution requests.
// It handles "Google's DNS over HTTPS using JSON" requests, as well as "DoH"
// request.
func (s *Server) Resolve(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	// Identify DoH requests:
	//  - GET requests have a "dns=" query parameter.
	//  - POST requests have a content-type = application/dns-message.
	if req.Method == "GET" && req.FormValue("dns") != "" {
		log.Printf("GET with dns wire received")
		dnsQuery, err := base64.RawURLEncoding.DecodeString(
			req.FormValue("dns"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		defer timeTrack(time.Now(), "timeTrack:resolveDOH DNS lookup")
		s.resolveDoH(w, dnsQuery)
		return
	}

	if req.Method == "POST" {
		ct, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if ct == "application/dns-message" {
			log.Printf("POST with dns wire received")

			// Limit the size of request to 4k.
			dnsQuery, err := ioutil.ReadAll(io.LimitReader(req.Body, 4092))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			defer timeTrack(time.Now(), "timeTrack:resolveDOH DNS lookup")
			s.resolveDoH(w, dnsQuery)
			return
		}
	}

	// Fall back to Google's JSON, the laxer format.
	// It MUST have a "name" query parameter, so we use that for detection.
	if req.Method == "GET" && req.FormValue("name") != "" {
		log.Printf("GET with JSON format requested")
		defer timeTrack(time.Now(), "timeTrack:resolveJSON DNS lookup")
		s.resolveJSON(w, req)
		return
	}

	// Could not found how to handle this request.
	http.Error(w, "unknown request type", http.StatusUnsupportedMediaType)
}

// Resolve "Google's DNS over HTTPS using JSON" requests, and returns
// responses as specified in
// https://developers.google.com/speed/public-dns/docs/dns-over-https#api_specification.
func (s *Server) resolveJSON(w http.ResponseWriter, req *http.Request) {
	// Construct the DNS request from the http query.
	q, err := parseQuery(req.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r := &dns.Msg{}
	r.CheckingDisabled = q.cd
	r.SetQuestion(dns.Fqdn(q.name), q.rrType)

	if q.clientSubnet != nil {
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		e := new(dns.EDNS0_SUBNET)
		e.Code = dns.EDNS0SUBNET
		if ipv4 := q.clientSubnet.IP.To4(); ipv4 != nil {
			e.Family = 1 // IPv4 source address
			e.Address = ipv4
		} else {
			e.Family = 2 // IPv6 source address
			e.Address = q.clientSubnet.IP
		}
		e.SourceScope = 0

		_, maskSize := q.clientSubnet.Mask.Size()
		e.SourceNetmask = uint8(maskSize)

		o.Option = append(o.Option, e)
		r.Extra = append(r.Extra, o)
	}

	// Do the DNS request, get the reply.
	fromUp, err := dns.Exchange(r, s.Upstream)
	if err != nil {
		http.Error(w, err.Error(), http.StatusFailedDependency)
		return
	}

	if fromUp == nil {
		http.Error(w, err.Error(), http.StatusRequestTimeout)
		return
	}

	// Convert the reply to json, and write it back.
	jr := &dnsjson.Response{
		Status: fromUp.Rcode,
		TC:     fromUp.Truncated,
		RD:     fromUp.RecursionDesired,
		RA:     fromUp.RecursionAvailable,
		AD:     fromUp.AuthenticatedData,
		CD:     fromUp.CheckingDisabled,
	}

	for _, q := range fromUp.Question {
		rr := dnsjson.RR{
			Name: q.Name,
			Type: q.Qtype,
		}
		jr.Question = append(jr.Question, rr)
	}

	for _, a := range fromUp.Answer {
		hdr := a.Header()
		ja := dnsjson.RR{
			Name: hdr.Name,
			Type: hdr.Rrtype,
			TTL:  hdr.Ttl,
		}

		hs := hdr.String()
		ja.Data = a.String()[len(hs):]
		jr.Answer = append(jr.Answer, ja)
	}

	buf, err := json.Marshal(jr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(buf)
}

type query struct {
	name   string
	rrType uint16
	cd     bool

	// EDNS client subnet (address+mask).
	clientSubnet *net.IPNet
}

var (
	errEmptyName     = fmt.Errorf("empty name")
	errNameTooLong   = fmt.Errorf("name too long")
	errInvalidSubnet = fmt.Errorf("invalid edns_client_subnet")
	errIntOutOfRange = fmt.Errorf("invalid type (int out of range)")
	errUnknownType   = fmt.Errorf("invalid type (unknown string type)")
	errInvalidCD     = fmt.Errorf("invalid cd value")
)

func parseQuery(u *url.URL) (query, error) {
	q := query{
		name:         "",
		rrType:       1,
		cd:           false,
		clientSubnet: nil,
	}

	// Simplify the values map, as all our parameters are single-value only.
	vs := map[string]string{}
	for k, values := range u.Query() {
		if len(values) > 0 {
			vs[k] = values[0]
		} else {
			vs[k] = ""
		}
	}
	var ok bool
	var err error

	if q.name, ok = vs["name"]; !ok || q.name == "" {
		return q, errEmptyName
	}
	if len(q.name) > 253 {
		return q, errNameTooLong
	}

	if _, ok = vs["type"]; ok {
		q.rrType, err = stringToRRType(vs["type"])
		if err != nil {
			return q, err
		}
	}

	if cd, ok := vs["cd"]; ok {
		q.cd, err = stringToBool(cd)
		if err != nil {
			return q, err
		}
	}

	if clientSubnet, ok := vs["edns_client_subnet"]; ok {
		_, q.clientSubnet, err = net.ParseCIDR(clientSubnet)
		if err != nil {
			return q, errInvalidSubnet
		}
	}

	return q, nil
}

// stringToRRType converts a string into a DNS type constant.
// The string can be a number in the [1, 65535] range, or a canonical type
// string (case-insensitive, such as "A" or "aaaa").
func stringToRRType(s string) (uint16, error) {
	i, err := strconv.ParseInt(s, 10, 16)
	if err == nil {
		if 1 <= i && i <= 65535 {
			return uint16(i), nil
		}
		return 0, errIntOutOfRange
	}

	rrType, ok := dns.StringToType[strings.ToUpper(s)]
	if !ok {
		return 0, errUnknownType
	}
	return rrType, nil
}

func stringToBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "", "1", "true":
		// Note the empty string is intentionally considered true, as long as
		// the parameter is present in the query.
		return true, nil
	case "0", "false":
		return false, nil
	}

	return false, errInvalidCD
}

// Resolve DNS over HTTPS requests, as specified in
// https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-12.
func (s *Server) resolveDoH(w http.ResponseWriter, dnsQuery []byte) {
	r := &dns.Msg{}
	err := r.Unpack(dnsQuery)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Fatalf("Error unpakcing dnsQuery %v", err.Error())
		return
	}

	// Do the DNS request, get the reply.
	// TODO: Emit timing data on upstream resolver.
	fromUp, err := dns.Exchange(r, s.Upstream)

	if err != nil {
		http.Error(w, err.Error(), http.StatusFailedDependency)
		log.Fatalf("DNS request failed  %v", err.Error())
		return
	}

	if fromUp == nil {
		http.Error(w, "no response from upstream", http.StatusRequestTimeout)
		log.Fatalf("No response from upstream  %v", err.Error())
		return
	}

	packed, err := fromUp.Pack()
	if err != nil {
		http.Error(w, "cannot pack reply", http.StatusFailedDependency)
		log.Fatalf("cannot pack reply  %v", err.Error())
		return
	}

	// Write the response back.
	w.Header().Set("Content-type", "application/dns-message")
	// TODO: set cache-control based on the response.
	w.WriteHeader(http.StatusOK)
	w.Write(packed)
}
