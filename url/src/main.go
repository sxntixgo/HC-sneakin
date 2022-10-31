package main

import (
	"database/sql"
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
		id := r.URL.Query().Get("id")

		if id != "" {

			for _, invalid := range invalid_arr {
				if strings.Contains(strings.ToLower(id), invalid) {
					fmt.Fprintf(w, "id contains invalid keyword \"%s\"", invalid)
					return
				}
			}

			if id == "none" {
				http.ServeFile(w, r, "index.html")
			}

			// Connect to database
			db, err := sql.Open("postgres", "host=postgres port=5432 user=postgres password=password dbname=challenge_db sslmode=disable")
			defer db.Close()
			if err != nil {
				log.Fatal(err)
			}

			// Prepare query with SQLi vuln
			query := fmt.Sprintf("SELECT username, apikey FROM accounts WHERE username='%s';", id)

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

			// Username is not found
			content, err := ioutil.ReadFile("not_found.html")
			if err != nil {
				fmt.Fprintf(w, "error: %s", err)
				return
			}
			content_str := string(content)
			id = strings.Replace(strings.ToLower(id), "script", "", -1)
			content_str = strings.Replace(content_str, "{{username}}", id, 1)
			fmt.Fprintf(w, "%s", content_str)

		} else {
			http.Redirect(w, r, "/?id=none", 302)
		}

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
			redirect := fmt.Sprintf("/?id=%s", username)
			http.Redirect(w, r, redirect, 302)
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
