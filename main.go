package main

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"crypto/ed25519"
	"database/sql"
	"encoding/json"

	library "git.ailur.dev/ailur/fg-library/v2"
	authLibrary "git.ailur.dev/ailur/fg-nucleus-library"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"html/template"
	"io/fs"
	"net/http"
)

var ServiceInformation = library.Service{
	Name: "datatracker",
	Permissions: library.Permissions{
		Authenticate:              true,  // This service does require authentication
		Database:                  true,  // This service does require database access
		BlobStorage:               false, // This service does not require blob storage
		InterServiceCommunication: true,  // This service does require inter-service communication
		Resources:                 true,  // This service does require its HTTP templates and static files
	},
	ServiceID: uuid.MustParse("322dc186-04d2-4f69-89b5-403ab643cc1d"),
}

func logFunc(message string, messageType uint64, information library.ServiceInitializationInformation) {
	// Log the message to the logger service
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000002"), // Logger service
		MessageType:  messageType,
		SentAt:       time.Now(),
		Message:      message,
	}
}

func renderTemplate(statusCode int, w http.ResponseWriter, data map[string]interface{}, templatePath string, information library.ServiceInitializationInformation) {
	var err error
	var requestedTemplate *template.Template
	// Output ls of the resource directory
	requestedTemplate, err = template.ParseFS(information.ResourceDir, "templates/"+templatePath)
	if err != nil {
		logFunc(err.Error(), 2, information)
		renderString(500, w, "Sorry, something went wrong on our end. Error code: 01. Please report to the administrator.", information)
	} else {
		w.WriteHeader(statusCode)
		err = requestedTemplate.Execute(w, data)
		if err != nil {
			logFunc(err.Error(), 2, information)
			renderString(500, w, "Sorry, something went wrong on our end. Error code: 02. Please report to the administrator.", information)
		}
	}
}

func renderString(statusCode int, w http.ResponseWriter, data string, information library.ServiceInitializationInformation) {
	w.WriteHeader(statusCode)
	_, err := w.Write([]byte(data))
	if err != nil {
		logFunc(err.Error(), 2, information)
	}
}

func renderJSON(statusCode int, w http.ResponseWriter, data map[string]interface{}, information library.ServiceInitializationInformation) {
	w.WriteHeader(statusCode)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		logFunc(err.Error(), 2, information)
	}
}

func getUsername(token string, oauthHostName string, publicKey ed25519.PublicKey) (string, string, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return "", "", err
	}

	if !parsedToken.Valid {
		return "", "", errors.New("invalid token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.New("invalid token")
	}

	// Check if the token expired
	date, err := claims.GetExpirationTime()
	if err != nil || date.Before(time.Now()) || claims["sub"] == nil || claims["isOpenID"] == nil || claims["isOpenID"].(bool) {
		return "", "", errors.New("invalid token")
	}

	// Get the user's information
	var responseData struct {
		Username string `json:"username"`
		Sub      string `json:"sub"`
	}
	request, err := http.NewRequest("GET", oauthHostName+"/api/oauth/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", "", err
	}

	if response.StatusCode != 200 || response.Body == nil || response.Body == http.NoBody {
		return "", "", errors.New("invalid response")
	}

	err = json.NewDecoder(response.Body).Decode(&responseData)
	if err != nil {
		return "", "", err
	}

	return responseData.Sub, responseData.Username, nil
}

func verifyJwt(token string, publicKey ed25519.PublicKey, conn library.Database) (jwt.MapClaims, bool) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, false
	}

	if !parsedToken.Valid {
		return nil, false
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, false
	}

	// Check if the token expired
	date, err := claims.GetExpirationTime()
	if err != nil || date.Before(time.Now()) || claims["sub"] == nil || claims["isOpenID"] == nil || claims["isOpenID"].(bool) {
		return claims, false
	}

	// Check if the token is in users
	userUuid, err := uuid.MustParse(claims["sub"].(string)).MarshalBinary()
	if err != nil {
		return claims, false
	}

	var idCheck []byte
	err = conn.DB.QueryRow("SELECT id FROM users WHERE id = $1", userUuid).Scan(&idCheck)
	if err != nil || claims["sub"] != uuid.Must(uuid.FromBytes(idCheck)).String() {
		return claims, false
	}

	return claims, true
}

func Main(information library.ServiceInitializationInformation) *chi.Mux {
	var conn library.Database
	hostName := information.Configuration["hostName"].(string)

	// Initiate a connection to the database
	// Call service ID 1 to get the database connection information
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000001"), // Service initialization service
		MessageType:  1,                                                      // Request connection information
		SentAt:       time.Now(),
		Message:      nil,
	}

	// Wait for the response
	response := <-information.Inbox
	if response.MessageType == 2 {
		// This is the connection information
		// Set up the database connection
		conn = response.Message.(library.Database)
		if conn.DBType == library.Sqlite {
			// Create the RFCs table
			_, err := conn.DB.Exec("CREATE TABLE IF NOT EXISTS rfc (id INTEGER NOT NULL, year INTEGER NOT NULL, name TEXT NOT NULL, content TEXT NOT NULL, version TEXT NOT NULL, creator BLOB NOT NULL, UNIQUE(id, year))")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
			// Create the users table
			_, err = conn.DB.Exec("CREATE TABLE IF NOT EXISTS users (id BLOB NOT NULL)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
			// Create the comments table
			_, err = conn.DB.Exec("CREATE TABLE IF NOT EXISTS comments (id BLOB NOT NULL, rfcId INTEGER NOT NULL, rfcYear INTEGER NOT NULL, content TEXT NOT NULL, creator BLOB NOT NULL, creatorName TEXT NOT NULL, created INTEGER NOT NULL)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
		} else {
			// Create the RFCs table
			_, err := conn.DB.Exec("CREATE TABLE IF NOT EXISTS rfc (id SERIAL PRIMARY KEY, year INTEGER NOT NULL, name TEXT NOT NULL, content TEXT NOT NULL, version TEXT NOT NULL, creator BYTEA NOT NULL, UNIQUE(id, year))")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
			// Create the users table
			_, err = conn.DB.Exec("CREATE TABLE IF NOT EXISTS users (id BYTEA NOT NULL)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
			// Create the comments table
			_, err = conn.DB.Exec("CREATE TABLE IF NOT EXISTS comments (id BYTEA NOT NULL, rfcId INTEGER NOT NULL, rfcYear INTEGER NOT NULL, content TEXT NOT NULL, creator BYTEA NOT NULL, creatorName TEXT NOT NULL, created INTEGER NOT NULL)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
		}
	} else {
		// This is an error message
		// Log the error message to the logger service
		logFunc(response.Message.(error).Error(), 3, information)
	}

	// Ask the authentication service for the public key
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000004"), // Authentication service
		MessageType:  2,                                                      // Request public key
		SentAt:       time.Now(),
		Message:      nil,
	}

	var publicKey ed25519.PublicKey = nil

	// 3 second timeout
	go func() {
		time.Sleep(3 * time.Second)
		if publicKey == nil {
			logFunc("Timeout while waiting for the public key from the authentication service", 3, information)
		}
	}()

	// Wait for the response
	response = <-information.Inbox
	if response.MessageType == 2 {
		// This is the public key
		publicKey = response.Message.(ed25519.PublicKey)
	} else {
		// This is an error message
		// Log the error message to the logger service
		logFunc(response.Message.(error).Error(), 3, information)
	}

	// Ask the authentication service to create a new OAuth2 client
	urlPath, err := url.JoinPath(hostName, "/oauth")
	if err != nil {
		logFunc(err.Error(), 3, information)
	}

	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000004"), // Authentication service
		MessageType:  1,                                                      // Create OAuth2 client
		SentAt:       time.Now(),
		Message: authLibrary.OAuthInformation{
			Name:        "Data Tracker",
			RedirectUri: urlPath,
			KeyShareUri: "",
			Scopes:      []string{"openid"},
		},
	}

	oauthResponse := authLibrary.OAuthResponse{}

	// 3 second timeout
	go func() {
		time.Sleep(3 * time.Second)
		if oauthResponse == (authLibrary.OAuthResponse{}) {
			logFunc("Timeout while waiting for the OAuth response from the authentication service", 3, information)
		}
	}()

	// Wait for the response
	response = <-information.Inbox
	switch response.MessageType {
	case 0:
		// Success, set the OAuth response
		oauthResponse = response.Message.(authLibrary.OAuthResponse)
		logFunc("Initialized with App ID: "+oauthResponse.AppID, 0, information)
	case 1:
		// An error which is their fault
		logFunc(response.Message.(error).Error(), 3, information)
	case 2:
		// An error which is our fault
		logFunc(response.Message.(error).Error(), 3, information)
	default:
		// An unknown error
		logFunc("Unknown error", 3, information)
	}

	// Set up the router
	router := chi.NewRouter()

	// Set up the static routes
	staticDir, err := fs.Sub(information.ResourceDir, "static")
	if err != nil {
		logFunc(err.Error(), 3, information)
	} else {
		router.Handle("/dt-static/*", http.StripPrefix("/dt-static/", http.FileServerFS(staticDir)))
	}

	// Set up the API routes
	router.Post("/api/comment/add", func(w http.ResponseWriter, r *http.Request) {
		var commentData struct {
			RfcId    int    `json:"rfcId"`
			RfcYear  int    `json:"rfcYear"`
			Content  string `json:"content"`
			JwtToken string `json:"token"`
		}
		err := json.NewDecoder(r.Body).Decode(&commentData)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Get the username
		sub, username, err := getUsername(commentData.JwtToken, information.Configuration["hostName"].(string), publicKey)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JWT token"}, information)
			fmt.Println(err)
			return
		}

		subBytes, err := uuid.MustParse(sub).MarshalBinary()
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "10"}, information)
			fmt.Println(err)
			return
		}

		// Create the comment UUID
		commentId, err := uuid.NewRandom()
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "11"}, information)
			return
		}

		commentIdBytes, err := commentId.MarshalBinary()
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "12"}, information)
			return
		}

		// Add the comment to the database
		_, err = conn.DB.Exec("INSERT INTO comments (id, rfcId, rfcYear, content, creator, creatorName, created) VALUES ($1, $2, $3, $4, $5, $6, $7)", commentIdBytes, commentData.RfcId, commentData.RfcYear, commentData.Content, subBytes, username, time.Now().Unix())
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "13"}, information)
			fmt.Println(err)
			return
		}

		renderJSON(200, w, map[string]interface{}{"success": true, "author": username}, information)
	})

	router.Post("/api/comment/list", func(w http.ResponseWriter, r *http.Request) {
		var commentData struct {
			RfcId   int `json:"rfcId"`
			RfcYear int `json:"rfcYear"`
		}
		err := json.NewDecoder(r.Body).Decode(&commentData)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Get the list of comments
		rows, err := conn.DB.Query("SELECT id, content, creatorName, created FROM comments WHERE rfcId = $1 AND rfcYear = $2", commentData.RfcId, commentData.RfcYear)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "05"}, information)
			return
		}

		var comments []map[string]interface{}
		for rows.Next() {
			var created int
			var id []byte
			var content, creatorName string
			err = rows.Scan(&id, &content, &creatorName, &created)
			if err != nil {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "06"}, information)
				return
			}
			comments = append(comments, map[string]interface{}{
				"id":      uuid.Must(uuid.FromBytes(id)).String(),
				"content": content,
				"author":  creatorName,
			})
		}

		renderJSON(200, w, map[string]interface{}{
			"comments": comments,
		}, information)
	})

	router.Post("/api/comment/remove", func(w http.ResponseWriter, r *http.Request) {
		var commentData struct {
			Id       string `json:"id"`
			JwtToken string `json:"token"`
		}
		err := json.NewDecoder(r.Body).Decode(&commentData)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Get the username
		_, username, err := getUsername(commentData.JwtToken, information.Configuration["hostName"].(string), publicKey)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JWT token"}, information)
			return
		}

		// Parse the UUID
		commentDataId, err := uuid.Parse(commentData.Id)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid UUID"}, information)
			return
		}

		commentDataIdBytes, err := commentDataId.MarshalBinary()
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "12"}, information)
			return
		}

		// Remove the comment from the database
		affected, err := conn.DB.Exec("DELETE FROM comments WHERE id = $1 AND creatorName = $2", commentDataIdBytes, username)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				renderJSON(404, w, map[string]interface{}{"error": "Comment not found"}, information)
				return
			} else {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "13"}, information)
				return
			}
		}

		rowsAffected, err := affected.RowsAffected()
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "14"}, information)
			return
		}

		if rowsAffected == 0 {
			renderJSON(404, w, map[string]interface{}{"error": "Comment not found"}, information)
			return
		}

		renderJSON(200, w, map[string]interface{}{"success": true}, information)
	})

	router.Get("/api/rfc/list", func(w http.ResponseWriter, r *http.Request) {
		// Get the list of RFCs
		rows, err := conn.DB.Query("SELECT name, id, year, version FROM rfc")
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "01"}, information)
			return
		}

		var rfcs []map[string]interface{}
		for rows.Next() {
			var name, version string
			var id, year int
			err = rows.Scan(&name, &id, &year, &version)
			if err != nil {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "02"}, information)
				return
			}
			rfcs = append(rfcs, map[string]interface{}{
				"name":    name,
				"id":      id,
				"year":    year,
				"version": version,
			})
		}

		renderJSON(200, w, map[string]interface{}{
			"rfcs": rfcs,
		}, information)
	})

	router.Post("/api/rfc/add", func(w http.ResponseWriter, r *http.Request) {
		var rfcData struct {
			Name     string `json:"name"`
			Content  string `json:"content"`
			Version  string `json:"version"`
			Year     int    `json:"year"`
			Id       int    `json:"id"`
			JwtToken string `json:"token"`
		}
		err := json.NewDecoder(r.Body).Decode(&rfcData)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		var claims jwt.MapClaims
		// Verify the JWT token
		var ok bool
		claims, ok = verifyJwt(rfcData.JwtToken, publicKey, conn)
		if !ok {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JWT token"}, information)
			return
		}

		// Add the rfc to the database
		userid, err := uuid.MustParse(claims["sub"].(string)).MarshalBinary()
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "03"}, information)
		}

		_, err = conn.DB.Exec("INSERT INTO rfc (id, year, name, content, version, creator) VALUES ($1, $2, $3, $4, $5, $6)", rfcData.Id, rfcData.Year, rfcData.Name, rfcData.Content, rfcData.Version, userid)
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "04"}, information)
			return
		}

		renderJSON(200, w, map[string]interface{}{"success": true}, information)
	})

	router.Post("/api/rfc/remove", func(w http.ResponseWriter, r *http.Request) {
		var rfcData struct {
			Id       int    `json:"id"`
			Year     int    `json:"year"`
			JwtToken string `json:"token"`
		}
		err := json.NewDecoder(r.Body).Decode(&rfcData)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		// Verify the JWT token
		claims, ok := verifyJwt(rfcData.JwtToken, publicKey, conn)
		if !ok {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JWT token"}, information)
			return
		}

		// Remove the rfc from the database
		userid, err := uuid.MustParse(claims["sub"].(string)).MarshalBinary()
		if err != nil {
			renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "08"}, information)
		}

		_, err = conn.DB.Exec("DELETE FROM rfc WHERE creator = $1 AND id = $2 AND year = $3", userid, rfcData.Id, rfcData.Year)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				renderJSON(404, w, map[string]interface{}{"error": "RFC not found"}, information)
				return
			} else {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "09"}, information)
				return
			}
		}

		renderJSON(200, w, map[string]interface{}{"success": true}, information)
	})

	router.Post("/api/rfc/get", func(w http.ResponseWriter, r *http.Request) {
		var rfcData struct {
			Id   int `json:"id"`
			Year int `json:"year"`
		}
		err := json.NewDecoder(r.Body).Decode(&rfcData)
		if err != nil {
			renderJSON(400, w, map[string]interface{}{"error": "Invalid JSON"}, information)
			return
		}

		var content, name, version string
		err = conn.DB.QueryRow("SELECT content, name, version FROM rfc WHERE id = $1 AND year = $2", rfcData.Id, rfcData.Year).Scan(&content, &name, &version)
		if err != nil {
			if err != nil && errors.Is(err, sql.ErrNoRows) {
				renderJSON(404, w, map[string]interface{}{"error": "RFC not found"}, information)
				return
			} else {
				renderJSON(500, w, map[string]interface{}{"error": "Internal server error", "code": "07"}, information)
				return
			}
		}

		renderJSON(200, w, map[string]interface{}{
			"content": content,
			"name":    name,
			"version": version,
		}, information)
	})

	// Set up the template routes
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(200, w, map[string]interface{}{}, "index.html", information)
	})

	router.Get("/rfc", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(200, w, map[string]interface{}{}, "rfc.html", information)
	})

	router.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(200, w, map[string]interface{}{}, "admin.html", information)
	})

	router.Get("/oauth", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(200, w, map[string]interface{}{
			"ClientId": oauthResponse.AppID,
		}, "oauth.html", information)
	})

	return router
}
