// slurp s3 bucket enumerator
// Copyright (C) 2017 8c30ff1057d69a6a6f6dc2212d8ec25196c542acb8620eb4148318a4b10dd131
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Workiva/go-datastructures/queue"
	"github.com/jmoiron/jsonq"
	"github.com/joeguo/tldextract"
	"github.com/spf13/cobra"
	"golang.org/x/net/idna"
)

var exit bool
var dQ *queue.Queue
var dbQ *queue.Queue
var permutatedQ *queue.Queue
var extract *tldextract.TLDExtract
var checked int64
var sem chan int
var action string

type Domain struct {
	CN     string
	Domain string
	Suffix string
	Raw    string
}

type PermutatedDomain struct {
	Permutation string
	Domain      Domain
}

type Keyword struct {
	Permutation string
	Keyword     string
}

var rootCmd = &cobra.Command{
	Use: "slurp",
	Run: func(cmd *cobra.Command, args []string) {
		action = cobra.MousetrapHelpText
	},
}

var domainCmd = &cobra.Command{
	Use:   "domain",
	Short: "d",
	Run: func(cmd *cobra.Command, args []string) {
		action = "DOMAIN"
	},
}

var keywordCmd = &cobra.Command{
	Use:   "keyword",
	Short: "k",
	Run: func(cmd *cobra.Command, args []string) {
		action = "KEYWORD"
	},
}

var cfgPermutationsFile string
var cfgKeywords []string
var cfgDomains []string

func setFlags() {
	domainCmd.PersistentFlags().StringSliceVarP(&cfgDomains, "target", "t", []string{}, "Domains to enumerate s3 buckets; format: example1.com,example2.com,example3.com")
	domainCmd.PersistentFlags().StringVarP(&cfgPermutationsFile, "permutations", "p", "./permutations.json", "Permutations file location")

	keywordCmd.PersistentFlags().StringSliceVarP(&cfgKeywords, "target", "t", []string{}, "List of keywords to enumerate s3; format: keyword1,keyword2,keyword3")
	keywordCmd.PersistentFlags().StringVarP(&cfgPermutationsFile, "permutations", "p", "./permutations.json", "Permutations file location")
}

// PreInit initializes goroutine concurrency and initializes cobra
func PreInit() {
	setFlags()

	helpCmd := rootCmd.HelpFunc()

	var helpFlag bool

	newHelpCmd := func(c *cobra.Command, args []string) {
		helpFlag = true
		helpCmd(c, args)
	}
	rootCmd.SetHelpFunc(newHelpCmd)

	// domainCmd command help
	helpDomainCmd := domainCmd.HelpFunc()
	newDomainHelpCmd := func(c *cobra.Command, args []string) {
		helpFlag = true
		helpDomainCmd(c, args)
	}
	domainCmd.SetHelpFunc(newDomainHelpCmd)

	// keywordCmd command help
	helpKeywordCmd := keywordCmd.HelpFunc()
	newKeywordHelpCmd := func(c *cobra.Command, args []string) {
		helpFlag = true
		helpKeywordCmd(c, args)
	}
	keywordCmd.SetHelpFunc(newKeywordHelpCmd)

	// Add subcommands
	rootCmd.AddCommand(domainCmd)
	rootCmd.AddCommand(keywordCmd)

	err := rootCmd.Execute()

	if err != nil {
		log.Fatal(err)
	}

	if helpFlag {
		os.Exit(0)
	}
}

// ProcessQueue processes data stored in the queue
func ProcessQueue() {
	for {
		cn, err := dQ.Get(1)

		if err != nil {
			log.Print(err)
			continue
		}

		//log.Printf("Domain: %s", cn[0].(string))

		if !strings.Contains(cn[0].(string), "cloudflaressl") && !strings.Contains(cn[0].(string), "xn--") && len(cn[0].(string)) > 0 && !strings.HasPrefix(cn[0].(string), "*.") && !strings.HasPrefix(cn[0].(string), ".") {
			punyCfgDomain, err := idna.ToASCII(cn[0].(string))
			if err != nil {
				log.Print(err)
			}

			result := extract.Extract(punyCfgDomain)
			//domain := fmt.Sprintf("%s.%s", result.Root, result.Tld)

			d := Domain{
				CN:     punyCfgDomain,
				Domain: result.Root,
				Suffix: result.Tld,
				Raw:    cn[0].(string),
			}

			if punyCfgDomain != cn[0].(string) {
				err := fmt.Sprintf("%s is (punycode); AWS does not support internationalized buckets", cn[0].(string))
				log.Print(err)
			}

			if err == nil {
				dbQ.Put(d)
			}

			log.Printf("CN: %s\tDomain: %s", cn[0].(string), d)
		}
	}
}

// PermutateDomainRunner stores the dbQ results into the database
func PermutateDomainRunner() {
	for {
		dstruct, err := dbQ.Get(1)

		if err != nil {
			log.Print(err)
			continue
		}

		var d = dstruct[0].(Domain)

		//log.Printf("CN: %s\tDomain: %s.%s", d.CN, d.Domain, d.Suffix)

		pd := PermutateDomain(d.Domain, d.Suffix)

		for p := range pd {
			permutatedQ.Put(PermutatedDomain{
				Permutation: pd[p],
				Domain:      d,
			})
		}
	}
}

// PermutateKeywordRunner stores the dbQ results into the database
func PermutateKeywordRunner() {
	for {
		dstruct, err := dbQ.Get(1)

		if err != nil {
			log.Print(err)
			continue
		}

		var d = dstruct[0].(string)

		//log.Printf("CN: %s\tDomain: %s.%s", d.CN, d.Domain, d.Suffix)

		pd := PermutateKeyword(d)

		for p := range pd {
			permutatedQ.Put(Keyword{
				Keyword:     d,
				Permutation: pd[p],
			})
		}
	}
}

// CheckPermutations runs through all permutations checking them for PUBLIC/FORBIDDEN buckets
func CheckPermutations() {
	var max = runtime.NumCPU() * 5
	sem = make(chan int, max)

	for {
		sem <- 1
		dom, err := permutatedQ.Get(1)

		if err != nil {
			log.Print(err)
		}

		tr := &http.Transport{
			IdleConnTimeout:       3 * time.Second,
			ResponseHeaderTimeout: 3 * time.Second,
			MaxIdleConnsPerHost:   max,
			ExpectContinueTimeout: 1 * time.Second,
		}
		client := &http.Client{
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		go func(pd PermutatedDomain) {

			req, err := http.NewRequest("GET", "http://s3-1-w.amazonaws.com", nil)

			if err != nil {
				if !strings.Contains(err.Error(), "time") {
					log.Print(err)
				}

				permutatedQ.Put(pd)
				<-sem
				return
			}

			req.Host = pd.Permutation
			req.Header.Add("Host", req.Host)

			resp, err1 := client.Do(req)

			if err1 != nil {
				if strings.Contains(err1.Error(), "time") {
					permutatedQ.Put(pd)
					<-sem
					return
				}

				log.Print(err1)
				permutatedQ.Put(pd)
				<-sem
				return
			}

			defer resp.Body.Close()

			//log.Printf("%s (%d)", host, resp.StatusCode)

			if resp.StatusCode == 307 {
				loc := resp.Header.Get("Location")

				req, err := http.NewRequest("GET", loc, nil)

				if err != nil {
					log.Print(err)
				}

				resp, err1 := client.Do(req)

				if err1 != nil {
					if strings.Contains(err1.Error(), "time") {
						permutatedQ.Put(pd)
						<-sem
						return
					}

					log.Print(err1)
					permutatedQ.Put(pd)
					<-sem
					return
				}

				defer resp.Body.Close()

				if resp.StatusCode == 200 {
					log.Printf("[PUBLIC] %s.%s.%s", loc, pd.Domain.Domain, pd.Domain.Suffix)
				}
			} else if resp.StatusCode == 503 {
				permutatedQ.Put(pd)
			}

			checked++
			resp.Body.Close()
			<-sem
		}(dom[0].(PermutatedDomain))
	}
}

// CheckKeywordPermutations runs through all permutations checking them for PUBLIC/FORBIDDEN buckets
func CheckKeywordPermutations() {
	var max = runtime.NumCPU() * 5
	sem = make(chan int, max)

	for {
		sem <- 1
		dom, err := permutatedQ.Get(1)

		if err != nil {
			log.Print(err)
		}

		tr := &http.Transport{
			IdleConnTimeout:       3 * time.Second,
			ResponseHeaderTimeout: 3 * time.Second,
			MaxIdleConnsPerHost:   max,
			ExpectContinueTimeout: 1 * time.Second,
		}
		client := &http.Client{
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		go func(pd Keyword) {
			req, err := http.NewRequest("GET", "http://s3-1-w.amazonaws.com", nil)

			if err != nil {
				if !strings.Contains(err.Error(), "time") {
					log.Print(err)
				}

				permutatedQ.Put(pd)
				<-sem
				return
			}

			req.Host = pd.Permutation
			req.Header.Add("Host", req.Host)
			req.Header.Add("User-Agent", "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1)")

			resp, err1 := client.Do(req)

			if err1 != nil {
				if strings.Contains(err1.Error(), "time") {
					permutatedQ.Put(pd)
					<-sem
					return
				}

				log.Print(err1)
				permutatedQ.Put(pd)
				<-sem
				return
			}

			defer resp.Body.Close()

			//log.Printf("%s (%d)", host, resp.StatusCode)

			if resp.StatusCode == 307 {
				loc := resp.Header.Get("Location")

				req, err := http.NewRequest("GET", loc, nil)

				if err != nil {
					log.Print(err)
				}

				resp, err1 := client.Do(req)

				if err1 != nil {
					if strings.Contains(err1.Error(), "time") {
						permutatedQ.Put(pd)
						<-sem
						return
					}

					log.Print(err1)
					permutatedQ.Put(pd)
					<-sem
					return
				}

				defer resp.Body.Close()

				if resp.StatusCode == 200 {
					log.Printf("[PUBLIC] %s [%s]", loc, pd.Keyword)
				}
			} else if resp.StatusCode == 503 {
				permutatedQ.Put(pd)
			}

			checked++

			<-sem
		}(dom[0].(Keyword))
	}
}

// PermutateDomain returns all possible domain permutations
func PermutateDomain(domain, suffix string) []string {
	if _, err := os.Stat(cfgPermutationsFile); err != nil {
		log.Fatal(err)
	}

	jsondata, err := ioutil.ReadFile(cfgPermutationsFile)

	if err != nil {
		log.Fatal(err)
	}

	data := map[string]interface{}{}
	dec := json.NewDecoder(strings.NewReader(string(jsondata)))
	dec.Decode(&data)
	jq := jsonq.NewQuery(data)

	s3url, err := jq.String("s3_url")

	if err != nil {
		log.Fatal(err)
	}

	var permutations []string

	perms, err := jq.Array("permutations")

	if err != nil {
		log.Fatal(err)
	}

	// Our list of permutations
	for i := range perms {
		permutations = append(permutations, fmt.Sprintf(perms[i].(string), domain, s3url))
	}

	// Permutations that are not easily put into the list
	permutations = append(permutations, fmt.Sprintf("%s.%s.%s", domain, suffix, s3url))
	permutations = append(permutations, fmt.Sprintf("%s.%s", strings.Replace(fmt.Sprintf("%s.%s", domain, suffix), ".", "", -1), s3url))

	return permutations
}

// PermutateKeyword returns all possible keyword permutations
func PermutateKeyword(keyword string) []string {
	if _, err := os.Stat(cfgPermutationsFile); err != nil {
		log.Fatal(err)
	}

	jsondata, err := ioutil.ReadFile(cfgPermutationsFile)

	if err != nil {
		log.Fatal(err)
	}

	data := map[string]interface{}{}
	dec := json.NewDecoder(strings.NewReader(string(jsondata)))
	dec.Decode(&data)
	jq := jsonq.NewQuery(data)

	s3url, err := jq.String("s3_url")

	if err != nil {
		log.Fatal(err)
	}

	var permutations []string

	perms, err := jq.Array("permutations")

	if err != nil {
		log.Fatal(err)
	}

	// Our list of permutations
	for i := range perms {
		permutations = append(permutations, fmt.Sprintf(perms[i].(string), keyword, s3url))
	}

	return permutations
}

// Init does low level initialization before we can run
func Init() {
	var err error

	dQ = queue.New(1000)

	dbQ = queue.New(1000)

	permutatedQ = queue.New(1000)

	extract, err = tldextract.New("./tld.cache", false)

	if err != nil {
		log.Fatal(err)
	}
}

// PrintJob prints the queue sizes
func PrintJob() {
	for {
		log.Printf("dQ size: %d", dQ.Len())
		log.Printf("dbQ size: %d", dbQ.Len())
		log.Printf("permutatedQ size: %d", permutatedQ.Len())
		log.Printf("Checked: %d", checked)

		time.Sleep(10 * time.Second)
	}
}

func main() {
	PreInit()

	switch action {
	case "DOMAIN":
		Init()

		for i := range cfgDomains {
			if len(cfgDomains[i]) != 0 {
				punyCfgDomain, err := idna.ToASCII(cfgDomains[i])
				if err != nil {
					log.Fatal(err)
				}

				log.Printf("Domain %s is %s (punycode)", cfgDomains[i], punyCfgDomain)

				if cfgDomains[i] != punyCfgDomain {
					log.Printf("Internationalized domains cannot be S3 buckets (%s)", cfgDomains[i])
					continue
				}

				result := extract.Extract(punyCfgDomain)

				if result.Root == "" || result.Tld == "" {
					log.Printf("%s is not a valid domain", punyCfgDomain)
					continue
				}

				d := Domain{
					CN:     punyCfgDomain,
					Domain: result.Root,
					Suffix: result.Tld,
					Raw:    cfgDomains[i],
				}

				dbQ.Put(d)
			}
		}

		if dbQ.Len() == 0 {
			log.Fatal("Invalid domains format, see help")
		}

		//log.Print("Starting to process queue....")
		go ProcessQueue()

		//log.Print("Starting to stream certs....")
		go PermutateDomainRunner()

		log.Print("Starting to process permutations....")
		go CheckPermutations()

		for {
			// 3 second hard sleep; added because sometimes it's possible to switch exit = true
			// in the time it takes to get from dbQ.Put(d); we can't have that...
			// So, a 3 sec sleep will prevent an pre-mature exit; but in most cases shouldn't really be noticable
			time.Sleep(3 * time.Second)

			if exit {
				break
			}

			if permutatedQ.Len() != 0 || dbQ.Len() > 0 || len(sem) > 0 {
				if len(sem) == 1 {
					<-sem
				}
			} else {
				exit = true
			}
		}

	case "KEYWORD":
		Init()

		for i := range cfgKeywords {
			if len(cfgKeywords[i]) != 0 {
				dbQ.Put(cfgKeywords[i])
			}
		}

		if dbQ.Len() == 0 {
			log.Fatal("Invalid keywords format, see help")
		}

		//log.Print("Starting to stream certs....")
		go PermutateKeywordRunner()

		log.Print("Starting to process permutations....")
		go CheckKeywordPermutations()

		for {
			// 3 second hard sleep; added because sometimes it's possible to switch exit = true
			// in the time it takes to get from dbQ.Put(d); we can't have that...
			// So, a 3 sec sleep will prevent an pre-mature exit; but in most cases shouldn't really be noticable
			time.Sleep(3 * time.Second)

			if exit {
				break
			}

			if permutatedQ.Len() != 0 || dbQ.Len() > 0 || len(sem) > 0 {
				if len(sem) == 1 {
					<-sem
				}
			} else {
				exit = true
			}
		}
	default:
		log.Print("Check help")
		os.Exit(0)
	}
}
