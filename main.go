package main

import (
	"flag"
	"fmt"
	"github.com/skip2/go-qrcode"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	iFlag        = flag.String("i", "wlo1", "network interface")
	portFlag     = flag.String("p", "8000", "port number")
	ip4Flag      = flag.Bool("4", false, "use IPv4 only")
	dirFlag      = flag.String("d", ".", "directory to serve")
	passwordFlag = flag.String("pass", "", "set simple password protection")
	excludeFlag  = flag.String("exclude", "", "comma-separated list of files/directories to exclude")
)

func main() {
	flag.Parse()

	_ = log.New(os.Stdout, "", log.LstdFlags)

	fs := http.FileServer(http.Dir(*dirFlag))
	handler := fs

	if *passwordFlag != "" {
		handler = securityMiddleware(handler)
		logger := log.New(os.Stdout, "", log.LstdFlags)
		handler = logMiddleware(logger)(handler)

		handler = basicAuthMiddleware(*passwordFlag)(handler)
	}

	if *excludeFlag != "" {
		excluded := make(map[string]bool)
		excludedFiles := strings.Split(*excludeFlag, ",")
		fmt.Println(excludedFiles)
		for _, file := range excludedFiles {
			file = strings.TrimSpace(file)
			excluded["/"+file] = true
		}
		handler = excludeMiddleware(excluded)(handler)
	}

	ip := GetOutboundIP(*iFlag, *portFlag, *ip4Flag)
	url := fmt.Sprintf("http://%s:%s", ip, *portFlag)
	generateQRCode(url)

	fmt.Printf("Serving files from %s at %s\n", *dirFlag, url)
	if err := http.ListenAndServe(":"+*portFlag, handler); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func logMiddleware(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			logger.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
		})
	}
}

func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

func basicAuthMiddleware(password string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, pass, ok := r.BasicAuth()
			if !ok || pass != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Please enter password"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func excludeMiddleware(excluded map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Println(r.URL.Path)
			if excluded[r.URL.Path] {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func generateQRCode(url string) {
	qr, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		fmt.Printf("Failed to generate QR code: %v\n", err)
		return
	}

	fmt.Println("\nScan this QR code to access the server:")
	fmt.Println(qr.ToSmallString(false))
}

func GetOutboundIP(ifa string, port string, ip4 bool) string {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Name == ifa {
			addrs, _ := i.Addrs()
			for _, addr := range addrs {
				if ip4 {
					if len(strings.Split(addr.String(), ".")) == 4 {
						return strings.Split(addr.String(), "/")[0]
					}
				}
				if len(strings.Split(addr.String(), ":")) == 8 || (len(strings.Split(addr.String(), ":")) == 3 && strings.Split(addr.String(), ":")[0] == "" && strings.Split(addr.String(), ":")[1] == "" && strings.Split(strings.Split(addr.String(), ":")[2], "/")[0] == "1") {
					return "[" + strings.Split(addr.String(), "/")[0] + "]"
				}
			}
		}
	}

	return "localhost"
}
