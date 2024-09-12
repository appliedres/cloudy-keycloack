package keycloak

import (
	"context"
	"fmt"

	"github.com/Nerzal/gocloak/v13"
)

type KeyCloakConn struct {
	Address string
	User    string
	Pwd     string
	Realm   string
	Client  *gocloak.GoCloak
	Token   *gocloak.JWT
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
		Address: address,
		User:    user,
		Pwd:     pwd,
		Realm:   realm,
		Client:  client,
		Token:   token,
	}, nil
}

func (key *KeyCloakConn) Connect(ctx context.Context) error {
	client := gocloak.NewClient(key.Address)
	if key.Realm == "" {
		key.Realm = "master"
	}
	token, err := client.LoginAdmin(ctx, key.User, key.Pwd, key.Realm)
	if err != nil {
		return err
	}
	key.Client = client
	key.Token = token
	return nil
}

func (key *KeyCloakConn) NewOIDCWebClient(ctx context.Context, name string, url string, urlRedirect string, urlLogout string) (string, error) {
	rtn, err := key.Client.CreateClient(ctx, key.Token.AccessToken, key.Realm, gocloak.Client{
		WebOrigins:         &[]string{"*"},
		ClientID:           ptr(name),
		Name:               ptr(name),
		RootURL:            ptr(url),
		BaseURL:            ptr(url),
		RedirectURIs:       &[]string{url, urlRedirect},
		AdminURL:           ptr(url),
		PublicClient:       ptr(true),
		FrontChannelLogout: ptr(true),
		Attributes: &map[string]string{
			"post.logout.redirect.uris": "http://localhost:4200##http://localhost:4200/signout##http://localhost:4200/signin",
		},
	})
	return rtn, err
}

func ptr[T any](i T) *T {
	return &i
}

func (key *KeyCloakConn) SyncLdapNow(ctx context.Context, ldapname string, fullSync bool) error {
	var url string

	// http://localhost:33139/admin/realms/master/user-storage/bde8e545-e569-4bce-96fe-727599709f9b/sync?action=triggerFullSync
	url = key.Address + "admin/realms/" + key.Realm + "/user-storage/" + ldapname + "/sync"

	if fullSync {
		url += "?action=triggerFullSync"
	} else {
		url += "?action=triggerChangedUsersSync"
	}

	if response, postErr := key.Client.RestyClient().NewRequest().SetAuthToken(key.Token.AccessToken).Post(url); postErr != nil {
		return postErr
	} else {
		if response.StatusCode() != 200 {
			postErr = fmt.Errorf("got status code '%d' with response body '%s'", response.StatusCode(), response.String())
			return postErr
		}
	}
	return nil
}

func (key *KeyCloakConn) AddADLdapSync(ctx context.Context, host string, port string, baseDn string, user string, bindPwd string) (string, error) {

	url := fmt.Sprintf("ldaps://%v", host)
	fmt.Printf("Connecting to : %v\n", url)

	usersDN := fmt.Sprintf("CN=Users,%v", baseDn)
	bindDN := fmt.Sprintf("CN=%v,%v", "Administrator", usersDN)

	fmt.Printf("bindDN : %v\n", bindDN)
	r, err := key.Client.GetRealm(ctx, key.Token.AccessToken, key.Realm)
	if err != nil {
		return "", err
	}

	userFederationConfig := map[string][]string{
		"fullSyncPeriod":                       {"-1"},
		"pagination":                           {"false"},
		"startTls":                             {"false"},
		"usersDn":                              {usersDN},
		"connectionPooling":                    {"false"},
		"cachePolicy":                          {"DEFAULT"},
		"useKerberosForPasswordAuthentication": {"false"},
		"importEnabled":                        {"true"},
		"enabled":                              {"true"},
		"bindDn":                               {bindDN},
		"changedSyncPeriod":                    {"-1"},
		"usernameLDAPAttribute":                {"sAMAccountName"},
		"bindCredential":                       {bindPwd},
		"lastSync":                             {"1726156911"},
		"vendor":                               {"ad"},
		"uuidLDAPAttribute":                    {"objectGUID"},
		"allowKerberosAuthentication":          {"false"},
		"connectionUrl":                        {url},
		"syncRegistrations":                    {"true"},
		"authType":                             {"simple"},
		"krbPrincipalAttribute":                {"userPrincipalName"},
		"useTruststoreSpi":                     {"always"},
		"usePasswordModifyExtendedOp":          {"false"},
		"trustEmail":                           {"false"},
		"userObjectClasses":                    {"person, organizationalPerson, user"},
		"rdnLDAPAttribute":                     {"sAMAccountName"},
		"editMode":                             {"READ_ONLY"},
		"validatePasswordPolicy":               {"false"},
	}
	userFederation := gocloak.Component{
		Name:            gocloak.StringP("ldap"),
		ProviderID:      gocloak.StringP("ldap"),
		ProviderType:    gocloak.StringP("org.keycloak.storage.UserStorageProvider"),
		ParentID:        r.ID,
		ComponentConfig: &userFederationConfig,
	}
	ldapComponentId, err := key.Client.CreateComponent(ctx, key.Token.AccessToken, key.Realm, userFederation)
	if err != nil {
		return "", err
	}

	return ldapComponentId, nil
}
