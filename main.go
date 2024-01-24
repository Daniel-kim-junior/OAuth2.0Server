package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"text/template"

	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("secret"))

func main() {

	http.HandleFunc("/", RenderMainView)
	http.HandleFunc("/auth", RenderAuthView)
	http.HandleFunc("/auth/callback", Authenticate)
	log.Fatal(http.ListenAndServe(":1333", nil))
}

func RenderStaticTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, _ := template.ParseFiles(name)
	tmpl.Execute(w, data)
}

func RenderMainView(w http.ResponseWriter, r *http.Request) {
	RenderStaticTemplate(w, "main.html", nil)
}

func RenderAuthView(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Options = &sessions.Options{
		Path:   "/auth",
		MaxAge: 300,
	}
	state := RandToken()
	session.Values["state"] = state
	session.Save(r, w)
	RenderStaticTemplate(w, "auth.html", GetLoginURL(state))
}

func Authenticate(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	state := session.Values["state"]

	delete(session.Values, "state")
	session.Save(r, w)

	if state != r.FormValue("state") {
		http.Error(w, "Invalid session state", http.StatusUnauthorized)
		return
	}
	token, err := OAuthConf.Exchange(context.TODO(), r.FormValue("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	client := OAuthConf.Client(context.TODO(), token)
	userInfoResp, err := client.Get(UserInfoAPIEndpoint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer userInfoResp.Body.Close()
	userInfo, err := io.ReadAll(userInfoResp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var authUser User
	json.Unmarshal(userInfo, &authUser)
	session.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 86400,
	}

	session.Values["name"] = authUser.Name
	session.Values["email"] = authUser.Email
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}
