package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

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

			if cookie_arr[0] == "webapp_session" {

				cookie_arr, err := base64.StdEncoding.DecodeString(cookie_arr[1])

				if err != nil {
					fmt.Fprintf(w, "Error decoding Base64: %s\n Do you need to clear your cookies?", err)
					return
				}

				cookie_arr_str := string(cookie_arr)

				var web_session WebSession

				err = json.Unmarshal([]byte(cookie_arr_str), &web_session)

				if err != nil {
					fmt.Fprintf(w, "Error decoding JSON: %s\n Do you need to clear your cookies?", err)
					return
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

		w.Header().Set("Set-Cookie", "webapp_session=eyJ1c2VybmFtZSI6Im5vbmUiLCJsb2dnZWRpbiI6ZmFsc2V9; Max-Age:3600")
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
			cookie_content := fmt.Sprintf("{\"username\":\"%s\",\"loggedin\":true}", username)
			cookie_content_encoded := base64.StdEncoding.EncodeToString([]byte(cookie_content))
			webapp_session := fmt.Sprintf("webapp_session=%s; Max-Age:3600", cookie_content_encoded)
			w.Header().Set("Set-Cookie", webapp_session)
			http.Redirect(w, r, "/", 302)
		}
		// Username is not found
		http.ServeFile(w, r, "login_error.html")

	default:
		fmt.Fprintf(w, "Only GET and POST methods are allowed.")
		return
	}
}

func main() {
	http.HandleFunc("/", process)
	http.ListenAndServe(":8090", nil)
}
