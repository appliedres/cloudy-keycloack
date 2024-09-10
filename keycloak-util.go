package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
)

type KeyCloakConn struct {
	address string
	user    string
	pwd     string
	realm   string
	client  *gocloak.GoCloak
	jwt     *gocloak.JWT
}

func NewKeyCloakConn(ctx context.Context, address string, user string, pwd string, realm string) (*KeyCloakConn, error) {
	client := gocloak.NewClient(address)
	if realm == "" {
		realm = "master"
	}
	token, err := client.LoginAdmin(ctx, user, pwd, realm)
	if err != nil {
		return nil, err
	}

	return &KeyCloakConn{
		address: address,
		user:    user,
		pwd:     pwd,
		realm:   realm,
		client:  client,
		jwt:     token,
	}, nil
}

func (key *KeyCloakConn) NewOIDCWebClient(ctx context.Context, name string, url string, urlRedirect string, urlLogout string) {
	rtn, err := key.client.CreateClient(ctx, key.jwt.AccessToken, key.realm, gocloak.Client{
		WebOrigins:   &[]string{"*"},
		ClientID:     ptr(name),
		Name:         ptr(name),
		RootURL:      ptr(url),
		BaseURL:      ptr(url),
		RedirectURIs: &[]string{urlRedirect},
		AdminURL:     ptr(url),
		PublicClient: ptr(true),
	})

}

func ptr[T any](i T) *T {
	return &i
}
