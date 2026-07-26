package garmin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/AlexxIT/SmartScaleConnect/pkg/core"
	"github.com/gomodule/oauth1/oauth"
)

func (c *Client) Login(username, password string) error {
	// Retry up to 3 times with exponential backoff on rate limiting
	delays := []time.Duration{0, 5 * time.Second, 15 * time.Second}
	var err error
	for _, delay := range delays {
		if delay > 0 {
			time.Sleep(delay)
			// Reset cookie jar for fresh session
			jar, _ := cookiejar.New(nil)
			c.ssoClient.Jar = jar
		}
		var ticket string
		ticket, err = c.getTicket(username, password)
		if err == nil {
			return c.getCredentials(ticket)
		}
		if !strings.Contains(err.Error(), "rate limited") {
			return err
		}
	}
	return err
}

// browserUserAgent mimics a real browser to bypass Cloudflare TLS fingerprinting
// on Garmin SSO endpoints. Without this, requests are blocked as non-browser clients.
const browserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// getTicket - first stage exchange username and password to OAuth ticket
func (c *Client) getTicket(username, password string) (string, error) {
	const url1 = "https://sso.garmin.com/sso/embed?" +
		"id=gauth-widget&" +
		"embedWidget=true&" +
		"gauthHost=https://sso.garmin.com/sso"

	req1, err := http.NewRequest("GET", url1, nil)
	if err != nil {
		return "", err
	}
	req1.Header.Set("User-Agent", browserUserAgent)

	res, err := c.ssoClient.Do(req1)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	// 2. Get CSRF
	const url2 = "https://sso.garmin.com/sso/signin?" +
		"id=gauth-widget&" +
		"embedWidget=true&" +
		"gauthHost=https://sso.garmin.com/sso/embed&" +
		"redirectAfterAccountCreationUrl=https://sso.garmin.com/sso/embed&" +
		"redirectAfterAccountLoginUrl=https://sso.garmin.com/sso/embed&" +
		"service=https://sso.garmin.com/sso/embed&" +
		"source=https://sso.garmin.com/sso/embed"

	req2, err := http.NewRequest("GET", url2, nil)
	if err != nil {
		return "", err
	}
	req2.Header.Set("User-Agent", browserUserAgent)

	res, err = c.ssoClient.Do(req2)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	csrf := core.Between(string(body), `name="_csrf" value="`, `"`)

	// 3. Signin
	data := fmt.Sprintf(
		"username=%s&password=%s&embed=true&_csrf=%s",
		url.QueryEscape(username), url.QueryEscape(password), csrf,
	)

	req, err := http.NewRequest("POST", url2, strings.NewReader(data))
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", browserUserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", url2) // important

	res, err = c.ssoClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err = io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	ticket := core.Between(string(body), `embed?ticket=`, `"`)
	if ticket == "" {
		if msg := core.Between(string(body), `class="error">`, `<`); msg != "" {
			return "", errors.New("garmin: " + msg)
		}
		if core.Between(string(body), `"status-code":"`, `"`) == "429" {
			return "", errors.New("garmin: rate limited (429), retry later")
		}
		return "", errors.New("garmin: can't find ticket")
	}

	return ticket, nil
}

func (c *Client) initOAuth() error {
	if c.oauthClient != nil {
		return nil
	}

	res, err := http.Get("https://thegarth.s3.amazonaws.com/oauth_consumer.json")
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var consumer struct {
		Key    string `json:"consumer_key"`
		Secret string `json:"consumer_secret"`
	}

	if err = json.NewDecoder(res.Body).Decode(&consumer); err != nil {
		return nil
	}

	c.oauthClient = &oauth.Client{
		Credentials: oauth.Credentials{
			Token:  consumer.Key,
			Secret: consumer.Secret,
		},
	}

	return nil
}

// getCredentials - first stage exchange ticket to OAuth Token and Secret
func (c *Client) getCredentials(ticket string) error {
	if err := c.initOAuth(); err != nil {
		return err
	}

	url1 := fmt.Sprintf(
		"https://connectapi.garmin.com/oauth-service/oauth/preauthorized?"+
			"ticket=%s&"+
			"login-url=https://sso.garmin.com/sso/embed&"+
			"accepts-mfa-tokens=true",
		ticket,
	)

	req, err := http.NewRequest("GET", url1, nil)
	if err != nil {
		return err
	}

	if err = c.oauthClient.SetAuthorizationHeader(req.Header, nil, req.Method, req.URL, nil); err != nil {
		return err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return err
	}

	c.oauthToken = values.Get("oauth_token")
	c.oauthSecret = values.Get("oauth_token_secret")

	return nil
}

// refreshAccessToken - exchange OAuth Token and Secret to accessToken
func (c *Client) refreshAccessToken() error {
	if err := c.initOAuth(); err != nil {
		return err
	}

	const url1 = "https://connectapi.garmin.com/oauth-service/oauth/exchange/user/2.0"

	req, err := http.NewRequest("POST", url1, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	credentials := &oauth.Credentials{Token: c.oauthToken, Secret: c.oauthSecret}
	if err = c.oauthClient.SetAuthorizationHeader(req.Header, credentials, req.Method, req.URL, nil); err != nil {
		return err
	}

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err = json.NewDecoder(res.Body).Decode(&data); err != nil {
		return err
	}

	c.accessToken = data.AccessToken
	c.expiresTime = time.Now().Add(time.Duration(data.ExpiresIn) * time.Second)

	return nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.accessToken == "" || time.Now().After(c.expiresTime) {
		if err := c.refreshAccessToken(); err != nil {
			return nil, err
		}
	}

	req.Header.Add("Authorization", "Bearer "+c.accessToken)
	return c.client.Do(req)
}

func (c *Client) LoginWithToken(token string) error {
	c.oauthToken, c.oauthSecret, _ = strings.Cut(token, ":")

	res, err := c.Get("userprofile-service/userprofile/userProfileBase")
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return errors.New("garmin: can't login")
	}

	return nil
}

func (c *Client) Token() string {
	return c.oauthToken + ":" + c.oauthSecret
}
