package main

import (
	"crypto/tls"
	"fmt"
	"flag"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
	"github.com/evilsocket/islazy/log"
)


var murl string
var musername string
var mpassword string
var mpath string

func init() {
	log.Output = "/dev/stdout"
	log.Level = log.INFO
	log.OnFatal = log.ExitOnFatal
	log.DateTimeFormat = "02-01-2006 15:04:05"
	log.Format = "{datetime} {level:name} {message}"

	flag.StringVar(&murl, "url", "", "pfSense web url")
	flag.StringVar(&musername, "username", "admin", "pfSense admin username")
	flag.StringVar(&mpassword, "password", "pfsense", "pfSense admin password")
	flag.StringVar(&mpath, "path", "", "path to backup")
	flag.Parse()

	if murl == "" {
		fmt.Println("Usage of pfsense-backup-exporter:")
		flag.PrintDefaults()
		os.Exit(1)
	}
}

func handleCSRF(n *html.Node) (csrfToken string, found bool) {
	if n.Type == html.ElementNode && n.Data == "input" {
		m := make(map[string]string)
		for _, attr := range n.Attr {
			m[attr.Key] = attr.Val
		}
		if m["name"] == "__csrf_magic" {
			return  m["value"], true
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if csrfToken, found = handleCSRF(c); found {
			return
		}
	}

	return "", false
}

func Do() {

	options := cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}
	jar, err := cookiejar.New(&options)
	if err != nil {
		log.Fatal("[SETUP] Cannot setup Cookie JAR: %s", err.Error())
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{Timeout: 15 * time.Second, Jar: jar, Transport: tr}

	res, err := client.Get(murl)
	if err != nil {
		log.Fatal("[LOGIN] HTTP error: %s", err.Error())
	}
	defer res.Body.Close()
	doc, err := html.Parse(res.Body)
	csrfToken, found := handleCSRF(doc)
	if !found {
		log.Fatal("[LOGIN] Cannot get CSRF token")
	}

	values := make(url.Values)
	values.Set("login", "Login")
	values.Set("usernamefld", musername)
	values.Set("passwordfld", mpassword)
	values.Set("__csrf_magic", csrfToken)

	res, err = client.PostForm(murl + "/diag_backup.php", values)
	if err != nil {
		log.Fatal("[PRE-DL] HTTP error: %s", err.Error())
	}
	defer res.Body.Close()

	doc, err = html.Parse(res.Body)
	csrfToken, found = handleCSRF(doc)
	if !found {
		log.Fatal("[PRE-DL] Cannot get CSRF token, check username/password!")
	}

	values = make(url.Values)
	values.Set("Submit", "Download configuration")
	values.Set("__csrf_magic", csrfToken)
	res, err = client.PostForm(murl + "/diag_backup.php", values)
	if err != nil {
		log.Fatal("[DL] HTTP error: %s", err.Error())
	}
	defer res.Body.Close()

	filename := res.Header.Get("content-disposition")

	if filename == "" {
		doc, err = html.Parse(res.Body)
		csrfToken, found = handleCSRF(doc)
		if !found {
			log.Fatal("[PRE-DL] Cannot get CSRF token, check username/password!")
		}
		values = make(url.Values)
		values.Set("download", "Download configuration as XML")
		values.Set("__csrf_magic", csrfToken)
		res, err = client.PostForm(murl + "/diag_backup.php", values)
		if err != nil {
			log.Fatal("[DL] HTTP error: %s", err.Error())
		}
		defer res.Body.Close()

		filename = res.Header.Get("content-disposition")
	}

	filename = strings.ReplaceAll(filename, "attachment; filename=config-", "")
	filename = filename[0:len(filename)-6] + ".xml"

	if mpath != "" {
		mpath = strings.TrimRight(mpath, "\\")
		mpath = strings.TrimRight(mpath, "/")
		filename = mpath + "/" + filename
	}

	f, err := os.Create(filename)
	if err != nil {
		log.Fatal("[Post-DL] Cannot create file: %s", err.Error())
	}
	defer f.Close()
	_, err = io.Copy(f, res.Body)
	if err != nil {
		log.Fatal("[Post-DL] Cannot write file: %s", err.Error())
	}

	log.Info("Downloaded configuration file: " + filename)

}

func main() {

	log.Info("---------------------------------------------------------")
	log.Info("|                pfSense Backup Exporter                 |")
	log.Info("---------------------------------------------------------")

	Do()

}
