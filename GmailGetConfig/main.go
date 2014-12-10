package main

import (
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	_ "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"code.google.com/p/goauth2/oauth"
	gmail "code.google.com/p/google-api-go-client/gmail/v1"
	plus "code.google.com/p/google-api-go-client/plus/v1"
	gomail "gopkg.in/jpoehls/gophermail.v0"
)

var config = &oauth.Config{
	ClientId:     "207816891512-prjii4141rq0rkoha06d8av8jvsfaegh.apps.googleusercontent.com", // from https://code.google.com/apis/console/
	ClientSecret: "yuwRoqY3g9UuYWlcDbSoqDKT",                                                 // from https://code.google.com/apis/console/
	Scope:        gmail.MailGoogleComScope + " " + plus.PlusMeScope + " " + plus.UserinfoEmailScope,
	AuthURL:      "https://accounts.google.com/o/oauth2/auth",
	TokenURL:     "https://accounts.google.com/o/oauth2/token",
}

// Flags
var (
	configFile = flag.String("config_file", "", "configuration file containing client_id and client_secret in a JSON format")
	cacheToken = flag.Bool("cachetoken", true, "cache the OAuth token")
	debug      = flag.Bool("debug", false, "show HTTP traffic")
	read       = flag.Bool("read", false, "Read emails headers")
	send       = flag.Bool("send", false, "Requires to provide receiver email subject and body")
)

type inputConfig struct {
	ClientId     string  `json:"client_id"`
	ClientSecret string  `json:"client_secret"`
	Scope        *string `json:"scope,omitempty"`
}

type message struct {
	size    int64
	gmailID string
	date    string // retrieved from message header
	snippet string
}

func main() {
	flag.Parse()
	if 0 == len(*configFile) {
		fmt.Println("You need to specify the configuration file ")
		os.Exit(-1)
	}
	b, err := ioutil.ReadFile(*configFile)
	if nil != err {
		fmt.Println("Failed to read configuration error : ", err.Error())
		os.Exit(-1)
	}
	var ic inputConfig
	err = json.Unmarshal(b, &ic)
	if nil != err {
		fmt.Println("The configuration file is not correct : ", err.Error())
		os.Exit(-1)
	}
	config.ClientId = ic.ClientId
	config.ClientSecret = ic.ClientSecret
	if nil != ic.Scope {
		//Override the default scope
		config.Scope = *ic.Scope
	}

	client, current_user, err := getOAuthClient(config)
	if nil != err {
		fmt.Println("Failed to get user information " + err.Error())
		os.Exit(-1)
	}
	svc, err := gmail.New(client)
	if err != nil {
		log.Fatalf("Unable to create Gmail service: %v", err)
	}

	if *read {
		var total int64

		pageToken := ""
		for {
			req := svc.Users.Messages.List("me").Fields("messages(historyId,id,payload,raw,sizeEstimate,snippet,threadId)")
			if pageToken != "" {
				req.PageToken(pageToken)
			}
			r, err := req.Do()
			if err != nil {
				log.Fatalf("Unable to retrieve messages: %v", err)
			}

			log.Printf("Processing %v messages...\n", len(r.Messages))
			for _, m := range r.Messages {
				msg, err := svc.Users.Messages.Get("me", m.Id).Do()
				if err != nil {
					log.Fatalf("Unable to retrieve message %v: %v", m.Id, err)
				}

				date := ""
				subject := ""
				from := ""
				got_them := 3
				for _, h := range msg.Payload.Headers {
					if 0 == got_them {
						break
					}
					if h.Name == "Date" {
						date = h.Value
						got_them--
						continue
					}
					if h.Name == "Subject" {
						subject = h.Value
						got_them--
						continue
					}
					if h.Name == "From" {
						from = h.Value
						got_them--
						continue
					}
				}

				fmt.Println(fmt.Sprintf("[%s] %s <= %s", date, subject, from))
			}

			if r.NextPageToken == "" {
				break
			}
			break
			//pageToken = r.NextPageToken
		}
		log.Printf("total: %v\n", total)
	}
	if *send {
		if flag.NArg() != 3 {
			fmt.Println("Send requires 3 parameters")
			os.Exit(-1)
		}
		message := gmail.Message{}
		m := &gomail.Message{}
		fmt.Println(current_user.Emails)
		m.SetFrom(current_user.DisplayName + "<" + current_user.Emails[0].Value + ">")
		m.AddTo(flag.Arg(0))
		m.Subject = flag.Arg(1)
		m.Body = flag.Arg(2)
		b, err = m.Bytes()
		if nil != err {
			log.Fatalf("Failed to generated raw content %v", err)
		}
		message.Raw = base64.URLEncoding.EncodeToString(b)
		_, err := svc.Users.Messages.Send("me", &message).Do()
		if nil != err {
			log.Fatalf("\n\n####################\nUnable to send message %v\n\n###########\n", err)
		}
	}
}

func osUserCacheDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Caches")
	case "linux", "freebsd":
		return filepath.Join(os.Getenv("HOME"), ".cache")
	}
	log.Printf("TODO: osUserCacheDir on GOOS %q", runtime.GOOS)
	return "."
}

func tokenCacheFile(config *oauth.Config) string {
	hash := fnv.New32a()
	hash.Write([]byte(config.ClientId))
	hash.Write([]byte(config.ClientSecret))
	hash.Write([]byte(config.Scope))
	fn := fmt.Sprintf("gmail-get-config")
	return filepath.Join(osUserCacheDir(), url.QueryEscape(fn))
}

type saveTokenStruct struct {
	Token *oauth.Token
	User  *plus.Person
}

func tokenFromFile(file string) (*saveTokenStruct, error) {
	if !*cacheToken {
		return nil, errors.New("--cachetoken is false")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	t := new(saveTokenStruct)
	err = gob.NewDecoder(f).Decode(t)
	return t, err
}

func saveToken(file string, token *oauth.Token, person *plus.Person) {
	f, err := os.Create(file)
	if err != nil {
		log.Printf("Warning: failed to cache oauth token: %v", err)
		return
	}
	defer f.Close()
	s := saveTokenStruct{token, person}
	gob.NewEncoder(f).Encode(s)
}

func condDebugTransport(rt http.RoundTripper) http.RoundTripper {
	if *debug {
		return &logTransport{rt}
	}
	return rt
}

func getOAuthClient(config *oauth.Config) (*http.Client, *plus.Person, error) {
	cacheFile := tokenCacheFile(config)
	token, err := tokenFromFile(cacheFile)
	fromToken := true
	var tempToken *oauth.Token
	var person *plus.Person
	if err != nil {
		tempToken = tokenFromWeb(config)
		fromToken = false
	} else {
		log.Printf("Using cached token %#v from %q", token, cacheFile)
		tempToken = token.Token
		person = token.User
	}

	t := &oauth.Transport{
		Token:     tempToken,
		Config:    config,
		Transport: condDebugTransport(http.DefaultTransport),
	}
	c := t.Client()
	if !fromToken {

		psv, err := plus.New(c)
		if nil != err {
			log.Printf("Failed to instantiate plus service %v", err)
			return nil, nil, err
		}
		person, err = psv.People.Get("me").Do()
		if nil != err {
			log.Printf("Failed to get current user")
			return nil, nil, err
		}
		saveToken(cacheFile, tempToken, person)
	}
	return c, person, nil
}

func tokenFromWeb(config *oauth.Config) *oauth.Token {
	ch := make(chan string)
	randState := fmt.Sprintf("st%d", time.Now().UnixNano())
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/favicon.ico" {
			http.Error(rw, "", 404)
			return
		}
		if req.FormValue("state") != randState {
			log.Printf("State doesn't match: req = %#v", req)
			http.Error(rw, "", 500)
			return
		}
		if code := req.FormValue("code"); code != "" {
			fmt.Fprintf(rw, "<h1>Success</h1>Authorized.")
			rw.(http.Flusher).Flush()
			ch <- code
			return
		}
		log.Printf("no code")
		http.Error(rw, "", 500)
	}))
	defer ts.Close()

	config.RedirectURL = ts.URL
	authUrl := config.AuthCodeURL(randState)
	go openUrl(authUrl)
	log.Printf("Authorize this app at: %s", authUrl)
	code := <-ch
	log.Printf("Got code: %s", code)

	t := &oauth.Transport{
		Config:    config,
		Transport: condDebugTransport(http.DefaultTransport),
	}
	_, err := t.Exchange(code)
	if err != nil {
		log.Fatalf("Token exchange error: %v", err)
	}

	return t.Token
}

func openUrl(url string) {
	//try := []string{"xdg-open", "google-chrome", "open"}
	//for _, bin := range try {
	//	err := exec.Command(bin, url).Run()
	//	if err == nil {
	//		return
	//	}
	//}
	log.Printf("Error opening URL in browser.")
}

func valueOrFileContents(value string, filename string) string {
	if value != "" {
		return value
	}
	slurp, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error reading %q: %v", filename, err)
	}
	return strings.TrimSpace(string(slurp))
}
