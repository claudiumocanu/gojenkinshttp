package jenkins

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
)

const (
	defaultBaseURL = "http://localhost:8080/"
)

var (
	errEmptyCrumb      = errors.New("could not generate a Jenkins crumb")
	errInvalidUrl      = errors.New("the Url is invalid")
	errInvalidUsername = errors.New("the Username is invalid")
	errInvalidPassword = errors.New("the Password is invalid")
)

type JenkinsClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type BasicCredentials struct {
	username string
	password string
}

type Client struct {
	// clientMu protects the client during calls that modify the CheckRedirect func.
	clientMu sync.Mutex
	// HTTP client used to communicate with the API.
	client *http.Client

	// Base URL for API requests. Defaults to localhost:8080, but can be set to a domain endpoint.
	// BaseURL should always be specified with a trailing slash.
	BaseURL *url.URL

	// basicCredentials are used to generate the Authorization header for all requests using this client
	basicCredentials BasicCredentials

	/*
		CSRF protection uses a token (called crumb in Jenkins) that is created by Jenkins and sent to the user.
		Any form submissions or similar action resulting in modifications, like triggering builds or changing
		configuration, requires that the crumb be provided. The crumb contains information identifying the user it was
		created for, so submissions with another user’s token would be rejected. All of this happens in the background
		and	has no visible impact except in rare circumstances, e.g., after a user’s session expired and they logged in
		again.
	*/
	crumb string

	// Services used for talking to different parts of the Jenkins API.
	// TODO: I may not implement this part and just provide a bare client which is taking care of auth and the baseUrl
}

// Client returns the http.Client used by this Jenkins client.
func (c *Client) Client() *http.Client {
	c.clientMu.Lock()
	defer c.clientMu.Unlock()
	clientCopy := *c.client
	return &clientCopy
}

// NewClient returns a new Jenkins API client.
// If a nil httpClient is provided, a new http.Client will be used.
// To use API methods which require more things to be done in the client, provide your own client here.
// If a nil rawJenkinsUrl is provided, the defaultBaseUrl is used
// The username and password are mandatory.
func NewClient(httpClient *http.Client, rawJenkinsUrl, username, password *string) (JenkinsClient, error) {
	// Validate mandatory parameters
	if username == nil {
		return nil, errInvalidUsername
	}
	if password == nil {
		return nil, errInvalidPassword
	}
	basicCredentials := BasicCredentials{
		username: *username,
		password: *password,
	}

	// Either use the defaultBaseURL or the one provided
	baseUrl, err := url.Parse(defaultBaseURL)
	if err != nil {
		return nil, fmt.Errorf("the defaultBaseURL is malformed: %w", err)
	}
	if rawJenkinsUrl != nil {
		baseUrl, err = url.Parse(*rawJenkinsUrl)
		if err != nil {
			err = fmt.Errorf("%s: %w", errInvalidUrl.Error(), err)
			return nil, err
		}
	}

	if httpClient == nil {
		httpClient = &http.Client{}
	}

	crumb, err := getCrumb(baseUrl, basicCredentials)
	if err != nil {
		return nil, err
	}

	c := &Client{
		client:  httpClient,
		BaseURL: baseUrl,
		basicCredentials: BasicCredentials{
			username: *username,
			password: *password,
		},
		crumb: *crumb,
	}
	return c, nil
}

// The expected response from the Jenkins Crumb Issuer
type crumbRes struct {
	Class             string `json:"_class,omitempty"`
	Crumb             string `json:"crumb,omitempty"`
	CrumbRequestField string `json:"crumbRequestField,omitempty"`
}

// Returns a crumb, given a jenkins URL and basic credentials.
// jenkinsUrl should always be specified with a trailing slash.
// Returns nil and an error if the crumb cannot be generated.
func getCrumb(jenkinsUrl *url.URL, basicCreds BasicCredentials) (*string, error) {

	crumbIssuerUrl := fmt.Sprintf("%s%s", jenkinsUrl.String(), "crumbIssuer/api/json")

	req, err := http.NewRequest("GET", crumbIssuerUrl, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(basicCreds.username, basicCreds.password)
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var resObj crumbRes
	json.Unmarshal(body, &resObj)
	if resObj.Crumb == "" {
		return nil, errEmptyCrumb
	}
	return &resObj.Crumb, nil

}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(c.basicCredentials.username, c.basicCredentials.password)
	return c.client.Do(req)
}
