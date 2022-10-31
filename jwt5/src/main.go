package main

import (
	"crypto/tls"
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
)

type WebSession struct {
	Username string
	Loggedin bool
}

func process(w http.ResponseWriter, r *http.Request) {
	var invalid_arr = [...]string{
		"alter", "create", "drop", "delete", "exec", "insert", "select", "union", "update", "where", "having", "'",
	}

	if r.URL.Path != "/" {
		http.Error(w, "404 not found.", http.StatusNotFound)
	}

	switch r.Method {

	case "GET":
		headers := r.Header
		cookie, ok := headers["Cookie"]
		if ok {
			cookie_str := strings.Join(cookie, "")
			cookie_arr := strings.SplitN(cookie_str, "=", 2)

			if cookie_arr[0] == "webapp_session" && cookie_arr[1] != "" {

				//verify JWT
				var token *jwt.Token
				var parser jwt.Parser
				var err error

				token, _, err = parser.ParseUnverified(cookie_arr[1], jwt.MapClaims{})

				if err != nil {
					fmt.Fprintf(w, "Invalid token: %s", cookie_arr[1])
					return
				}

				pubKey, err := ioutil.ReadFile("pub_server.key")
				if err != nil {
					fmt.Fprintf(w, "Error reading key file")
					return
				}

				switch token.Header["alg"] {

				case "RS256":

					key, _ := jwt.ParseRSAPublicKeyFromPEM(pubKey)

					token, err = jwt.Parse(cookie_arr[1], func(token *jwt.Token) (interface{}, error) {
						// Don't forget to validate the alg is what you expect:
						if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
							return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
						}

						return key, nil
					})

				case "HS256":

					token, err = jwt.Parse(cookie_arr[1], func(token *jwt.Token) (interface{}, error) {
						// Don't forget to validate the alg is what you expect:
						if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
							return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
						}

						// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
						return pubKey, nil
					})

				default:
					fmt.Fprintf(w, "Error validating JWT: invalid signing algorithm\nDo you need to clear your cookies?")
					return
				}

				if token.Valid == false {
					fmt.Fprintf(w, "Error validating JWT: %s", err)
					return
				}

				var web_session WebSession

				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

					web_session.Username = fmt.Sprintf("%v", claims["username"])
					if fmt.Sprintf("%v", claims["loggedin"]) == "true" {
						web_session.Loggedin = true
					} else {
						web_session.Loggedin = false
					}

				}

				if web_session.Loggedin {

					// Checks for SQLi attacks
					for _, invalid := range invalid_arr {
						if strings.Contains(strings.ToLower(web_session.Username), invalid) {
							fmt.Fprintf(w, "username contains invalid keyword \"%s\"", invalid)
							return
						}
					}

					// Connect to database
					db, err := sql.Open("postgres", "host=postgres port=5432 user=postgres password=password dbname=challenge_db sslmode=disable")
					defer db.Close()
					if err != nil {
						log.Fatal(err)
					}

					// Prepare query
					query := fmt.Sprintf("SELECT username, apikey FROM accounts WHERE username='%s';", web_session.Username)

					rows, err := db.Query(query)
					if err != nil {
						// Query error, we show the error message and the query
						fmt.Fprintf(w, "database error: %s \nquery: %s", err, query)
						return
					}
					defer rows.Close()

					for rows.Next() {
						var username string
						var apikey string
						err := rows.Scan(&username, &apikey)
						if err != nil {
							fmt.Fprintf(w, "error: %s", err)
							return
						}
						// Username is found
						content, err := ioutil.ReadFile("home.html") // the file is inside the local directory
						if err != nil {
							fmt.Fprintf(w, "error: %s", err)
							return
						}
						content_str := string(content)
						content_str = strings.Replace(content_str, "{{username}}", username, 1)
						content_str = strings.Replace(content_str, "{{apikey}}", apikey, 1)
						fmt.Fprintf(w, "%s", content_str)
						return
					}
				}
			}
		}

		w.Header().Set("Set-Cookie", "webapp_session=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dnZWRpbiI6ZmFsc2UsInVzZXJuYW1lIjoibm9uZSJ9.RplzQJgFVIh4qTFUsJ5ealVtVNkrqoK3AnBMAb2keoq99s1wOEJCdTZxjJ0EzGjZV8QNHXyQmT_trkYOoJ73Pt3IsT7jVWxNXN-fXeKJiwu_GZKxrvZcba5z1fs424q6AUDNFmEVdpQ9IKxj3eY4c50XT1jWyHMYS6PqJ0z7GIl-c0I4O7HHyOPbWo1W_MJDfzRhKgqJWMLLky7osW_rdiuM5zcP01Dmy9STqh0uPYL2oGZxoJRhDMEuYAnhkYWzQ6ICoPOsHFmlZj7xudWEHVvOvf5l-omQSKu7sc7PqMiErLgZbAjpIHmpsqUJ3YRcCgwKY2qY4B6mj3sTis5A6g; Max-Age:3600")
		http.ServeFile(w, r, "index.html")

	case "POST":

		err := r.ParseForm()
		if err != nil {
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		// Checks for other forms of SQLi attacks
		for _, invalid := range invalid_arr {
			if strings.Contains(strings.ToLower(username), invalid) {
				fmt.Fprintf(w, "username contains invalid keyword \"%s\"", invalid)
				return
			}
			if strings.Contains(strings.ToLower(password), invalid) {
				fmt.Fprintf(w, "password contains invalid keyword \"%s\"", invalid)
				return
			}
		}

		// Connect to database
		db, err := sql.Open("postgres", "host=postgres port=5432 user=postgres password=password dbname=challenge_db sslmode=disable")
		defer db.Close()
		if err != nil {
			log.Fatal(err)
		}

		// Prepare query with SQLi vuln
		query := fmt.Sprintf("SELECT username FROM accounts WHERE username='%s' AND password='%s';", username, password)

		rows, err := db.Query(query)
		if err != nil {
			// Query error, we show the error message and the query
			fmt.Fprintf(w, "database error: %s \nquery: %s", err, query)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var username string
			err := rows.Scan(&username)
			if err != nil {
				fmt.Fprintf(w, "error: %s", err)
				return
			}

			// Username is found
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"username": username,
				"loggedin": true,
			})

			rsa256Key, err := os.ReadFile("server.key")
			if err != nil {
				fmt.Fprintf(w, "Error reading key file")
				return
			}

			key, _ := jwt.ParseRSAPrivateKeyFromPEM(rsa256Key)
			tokenString, err := token.SignedString(key)

			webapp_session := fmt.Sprintf("webapp_session=%s; Max-Age:3600", tokenString)
			w.Header().Set("Set-Cookie", webapp_session)
			http.Redirect(w, r, "/", 302)
		}
		// Username is not found
		http.ServeFile(w, r, "login_error.html")
		return

	default:
		fmt.Fprintf(w, "Only GET and POST methods are allowed.")
	}
}

func main() {
	addr := flag.String("127.0.0.1", ":8090", "HTTPS network address")
	certFile := flag.String("certfile", "server.crt", "certificate PEM file")
	keyFile := flag.String("keyfile", "server.key", "key PEM file")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", process)

	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
		},
	}

	err := srv.ListenAndServeTLS(*certFile, *keyFile)
	log.Fatal(err)

}
