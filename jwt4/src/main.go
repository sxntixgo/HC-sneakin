package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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

	if r.URL.Path == "/robots.txt" {
		http.ServeFile(w, r, "robots.txt")
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
				var key_path string

				token, _, err = parser.ParseUnverified(cookie_arr[1], jwt.MapClaims{})

				if err != nil {
					fmt.Fprintf(w, "Invalid token: %s", cookie_arr[1])
					return
				}

				if kid, ok := token.Header["kid"]; ok {
					key_path, err = url.QueryUnescape(fmt.Sprintf("%v", kid))
				} else {
					fmt.Fprintf(w, "Invalid token: \"kid\" not found in header\nDo you need to clear your cookies?")
					return
				}

				if err != nil {
					fmt.Fprintf(w, "Error decoding kid")
					return
				}

				if strings.Contains(key_path, "../") {
					fmt.Fprintf(w, "Path traversal is not available")
					return
				}

				hmacKey, err := ioutil.ReadFile(key_path)
				if err != nil {
					fmt.Fprintf(w, "Error reading key file")
					return
				}

				token, err = jwt.Parse(cookie_arr[1], func(token *jwt.Token) (interface{}, error) {
					// Don't forget to validate the alg is what you expect:
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
					}

					// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
					return []byte(hmacKey), nil
				})

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

		w.Header().Set("Set-Cookie", "webapp_session=eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS50eHQifQ.eyJsb2dnZWRpbiI6ZmFsc2UsInVzZXJuYW1lIjoibm9uZSJ9.uPgvwe8lBIZw5VO29IMd8GIMn4IER2hL3_3Z4YkpqJV5BgmzDwEudI9_H_Q2uutvbd7NhUa2__TIQaWdobkrRQ; Max-Age:3600")
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
			token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
				"username": username,
				"loggedin": true,
			})

			token.Header["kid"] = "key.txt"

			hmacKey, err := ioutil.ReadFile("key.txt")
			if err != nil {
				fmt.Fprintf(w, "Error reading key file")
				return
			}

			tokenString, err := token.SignedString([]byte(hmacKey))

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
	http.HandleFunc("/", process)
	http.ListenAndServe(":8090", nil)
}
