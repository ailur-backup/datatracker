package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"syscall/js"
	"time"
)

func sha256Base64(s string) string {
	hashed := sha256.Sum256([]byte(s))
	encoded := base64.URLEncoding.EncodeToString(hashed[:])
	encoded = strings.TrimRight(encoded, "=")
	return encoded
}

func randomChars(length int) (string, error) {
	var saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if length <= 0 {
		return "", errors.New("salt length must be greater than 0")
	}

	salt := make([]byte, length)
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	for i := range salt {
		salt[i] = saltChars[int(randomBytes[i])%len(saltChars)]
	}
	return string(salt), nil
}

func main() {
	// Clear local storage
	localStorage := js.Global().Get("localStorage")
	localStorage.Call("clear")

	statusBox := js.Global().Get("document").Call("getElementById", "statusBox")
	tryAgain := js.Global().Get("document").Call("getElementById", "tryAgain")

	go func() {
		// Check if the URL has a code
		urlParams, err := url.ParseQuery(strings.TrimPrefix(js.Global().Get("window").Get("location").Get("search").String(), "?"))
		if err != nil {
			statusBox.Set("innerText", "Error parsing URL: "+err.Error())
			tryAgain.Set("style", "")
			return
		}

		if urlParams.Has("code") {
			// Set the status box
			statusBox.Set("innerText", "Authenticating...")

			// Create the form data
			var formData = url.Values{}
			formData.Set("grant_type", "authorization_code")
			formData.Set("code", urlParams.Get("code"))
			formData.Set("client_id", js.Global().Get("document").Call("getElementById", "clientId").Get("innerText").String())
			formData.Set("redirect_uri", js.Global().Get("window").Get("location").Get("origin").String()+"/oauth")
			formData.Set("code_verifier", localStorage.Call("getItem", "OAUTH-verifier").String())

			// Create the request
			requestUri, err := url.JoinPath(js.Global().Get("document").Call("getElementById", "authorizationUri").Get("innerText").String(), "/api/oauth/token")
			if err != nil {
				statusBox.Set("innerText", "Error joining URL: "+err.Error())
				tryAgain.Set("style", "")
				return
			}

			response, err := http.Post(requestUri, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
			if err != nil {
				statusBox.Set("innerText", "Error contacting server: "+err.Error())
				tryAgain.Set("style", "")
				return
			}

			// Read the response
			var responseMap map[string]interface{}
			decoder := json.NewDecoder(response.Body)
			err = decoder.Decode(&responseMap)
			if err != nil {
				statusBox.Set("innerText", "Error decoding server response: "+err.Error())
				tryAgain.Set("style", "")
				return
			}

			// Close the response body
			err = response.Body.Close()
			if err != nil {
				fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
			}

			if response.StatusCode == 200 {
				// Fetch userinfo
				requestUri, err := url.JoinPath(js.Global().Get("document").Call("getElementById", "authorizationUri").Get("innerText").String(), "/api/oauth/userinfo")
				if err != nil {
					statusBox.Set("innerText", "Error joining URL: "+err.Error())
					tryAgain.Set("style", "")
					return
				}

				// Create the request
				request, err := http.NewRequest("GET", requestUri, nil)
				if err != nil {
					statusBox.Set("innerText", "Error creating request: "+err.Error())
					tryAgain.Set("style", "")
					return
				}

				// Set the authorization header
				request.Header.Set("Authorization", "Bearer "+responseMap["id_token"].(string))

				// Send the request
				response, err := http.DefaultClient.Do(request)
				if err != nil {
					statusBox.Set("innerText", "Error contacting server: "+err.Error())
					tryAgain.Set("style", "")
					return
				}

				// Read the response
				decoder = json.NewDecoder(response.Body)
				err = decoder.Decode(&responseMap)
				if err != nil {
					statusBox.Set("innerText", "Error decoding server response: "+err.Error())
					tryAgain.Set("style", "")
					return
				}

				// Close the response body
				err = response.Body.Close()
				if err != nil {
					fmt.Println("Could not close response body: " + err.Error() + ", memory leaks may occur")
				}

				// Save the username and token
				localStorage.Call("setItem", "CONFIG-username", responseMap["username"].(string))
				localStorage.Call("setItem", "SECRET-token", responseMap["access_token"].(string))

				// Remove the verifier
				localStorage.Call("removeItem", "OAUTH-verifier")

				// Set the status box
				statusBox.Set("innerText", "Successfully authenticated!")

				// Wait for 1 second
				time.Sleep(1 * time.Second)

				// Redirect to rfcs
				js.Global().Get("window").Get("location").Call("replace", "/rfc")
				return
			} else if response.StatusCode != 500 {
				statusBox.Set("innerText", responseMap["error"].(string))
				tryAgain.Set("style", "")
			} else {
				statusBox.Set("innerText", "Something went wrong! (error code: "+responseMap["code"].(string)+")")
				tryAgain.Set("style", "")
			}
		} else if urlParams.Has("error") {
			if urlParams.Get("error") == "access_denied" {
				statusBox.Set("innerText", "Access denied")
				tryAgain.Set("style", "")
			} else {
				statusBox.Set("innerText", "Authentication failed (error code: "+urlParams.Get("error")+")")
				tryAgain.Set("style", "")
			}
		} else {
			// Start the authorization process
			verifier, err := randomChars(128)
			if err != nil {
				statusBox.Set("innerText", "Error generating verifier: "+err.Error())
				tryAgain.Set("style", "")
				return
			}

			// Generate the challenge
			verifierChallenge := sha256Base64(verifier)

			// Save the verifier
			localStorage.Call("setItem", "OAUTH-verifier", verifier)

			// Redirect to the authorization page
			js.Global().Get("window").Get("location").Call("replace", js.Global().Get("document").Call("getElementById", "authorizationUri").Get("innerText").String()+"/authorize?response_type=code&client_id="+js.Global().Get("document").Call("getElementById", "clientId").Get("innerText").String()+"&redirect_uri="+url.QueryEscape(js.Global().Get("window").Get("location").Get("origin").String()+"/oauth")+"&code_challenge="+verifierChallenge+"&code_challenge_method=S256")
		}
	}()

	// Add event listener to try again button
	tryAgain.Call("addEventListener", "click", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// Redirect to the same URL without the query
		js.Global().Get("window").Get("location").Call("replace", js.Global().Get("window").Get("location").Get("origin").String()+js.Global().Get("window").Get("location").Get("pathname").String())
		return nil
	}))

	// Wait for events
	select {}
}
