package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/net/html"

	"github.com/gorilla/mux"
)

type AnalyzerRequest struct {
	Script string `json:"script"`
}

type AnalyzerResponse struct {
	SecurityIssues []string `json:"security_issues"`
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/analyze", analyzerHandler).Methods("POST")

	http.ListenAndServe(":8080", r)
}

func analyzerHandler(w http.ResponseWriter, r *http.Request) {
	var request AnalyzerRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	script := request.Script
	securityIssues := analyzeScript(script)

	response := AnalyzerResponse{securityIssues}
	json.NewEncoder(w).Encode(response)
}

func analyzeScript(script string) []string {
	securityIssues := make([]string, 0)

	// Tokenize the script
	tokens := strings.Split(script, " ")

	// Analyze each token
	for _, token := range tokens {
		switch token {
		case "eval":
			securityIssues = append(securityIssues, "Potential eval() vulnerability")
		case "system":
			securityIssues = append(securityIssues, "Potential system() vulnerability")
		default:
			continue
		}
	}

	return securityIssues
}