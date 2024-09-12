package keycloak

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Nerzal/gocloak/v13"
	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
)

type PageRequest struct {
	First int
	Max   int
}

// FACTORY
const Keycloak = "keycloak"
const PageSize = 100

func init() {
	cloudy.UserProviders.Register(Keycloak, &KeycloakUserManagerFactory{})
}

type KeycloakUserManagerFactory struct{}

func (umf *KeycloakUserManagerFactory) Create(cfg interface{}) (cloudy.UserManager, error) {
	return cfg.(*KeycloakUserManager), nil
}

func (umf *KeycloakUserManagerFactory) FromEnv(env *cloudy.Environment) (interface{}, error) {
	cfg := NewKeycloakUserManagerFromEnv(context.Background(), env)
	return cfg, nil
}

/// ------------- USER MANAGER

type KeycloakUserManager struct {
	address string
	user    string
	pwd     string
	realm   string
	client  *gocloak.GoCloak
	jwt     *gocloak.JWT
}

func NewKeycloakUserManager(address string, user string, pwd string, realm string) *KeycloakUserManager {
	return &KeycloakUserManager{
		address: address,
		user:    user,
		pwd:     pwd,
		realm:   realm,
	}
}

func NewKeycloakUserManagerFromEnv(ctx context.Context, env *cloudy.Environment) *KeycloakUserManager {
	cfg := &KeycloakUserManager{}
	cfg.address = env.Force("KEYCLOAK_HOST")
	cfg.user = env.Force("KEYCLOAK_USER")
	cfg.pwd = env.Force("KEYCLOAK_PWD")
	cfg.realm = env.Default("KEYCLOAK_REALM", "master")
	return cfg
}

func (um *KeycloakUserManager) connect(ctx context.Context) error {
	//FIXME : CHECK EXPIRED
	if um.jwt != nil {
		return nil
	}

	client := gocloak.NewClient(um.address)
	token, err := client.LoginAdmin(ctx, um.user, um.pwd, um.realm)
	if err != nil {
		return err
	}
	um.jwt = token
	um.client = client

	// Add all the attributes
	return um.AddUserAttributes(ctx, AdditionalAttributes)
}

// ForceUserName takes a proposed user name, validates it and transforms it.
// Then it checks to see if it is a real user
// Returns: string - updated user name, bool - if the user exists, error - if an error is encountered
func (um *KeycloakUserManager) ForceUserName(ctx context.Context, name string) (string, bool, error) {
	err := um.connect(ctx)
	if err != nil {
		return name, false, err
	}

	found, err := um.client.GetUsers(ctx, um.jwt.AccessToken, um.realm, gocloak.GetUsersParams{
		Username: &name,
		Exact:    gocloak.BoolP(true),
	})

	if err != nil {
		return name, false, err
	}

	if len(found) > 0 {
		return name, true, nil
	}

	return name, false, nil
}

func (um *KeycloakUserManager) ListUsers(ctx context.Context, filter string, attrs []string) (*[]models.User, error) {
	err := um.connect(ctx)
	if err != nil {
		return nil, err
	}

	params := gocloak.GetUsersParams{}
	all, err := um.client.GetUsers(ctx, um.jwt.AccessToken, um.realm, params)
	if err != nil {
		return nil, err
	}

	var users []models.User
	for _, usr := range all {
		users = append(users, *UserToCloudy(usr))
	}

	return &users, nil
}

func (um *KeycloakUserManager) listUsers(ctx context.Context, page interface{}, filter interface{}) ([]*models.User, interface{}, error) {
	err := um.connect(ctx)
	if err != nil {
		return nil, nil, err
	}

	var all []*models.User
	var nextPage *PageRequest
	for {
		some, next, err := um.listUserPage(ctx, nextPage)
		if err != nil {
			return all, nil, err
		}
		all = append(all, some...)
		if next == nil {
			return all, nil, nil
		}
		nextPage = next
	}
}

func (um *KeycloakUserManager) listUserPage(ctx context.Context, page *PageRequest) ([]*models.User, *PageRequest, error) {
	err := um.connect(ctx)
	if err != nil {
		return nil, nil, err
	}

	params := gocloak.GetUsersParams{}
	if page != nil {
		params.Max = cloudy.IntP(page.Max)
		params.First = cloudy.IntP(page.First)
	}

	var nextPage *PageRequest

	all, err := um.client.GetUsers(ctx, um.jwt.AccessToken, um.realm, params)
	if err != nil {
		return nil, nil, err
	}
	rtn := make([]*models.User, len(all))
	for i, keyUser := range all {
		rtn[i] = UserToCloudy(keyUser)
	}

	if len(all) == PageSize {
		first := 0
		if params.First != nil {
			first = *params.First
		}
		nextPage = &PageRequest{
			First: first + PageSize,
			Max:   PageSize,
		}
	}

	return rtn, nextPage, nil
}

// Retrieves a specific user.
func (um *KeycloakUserManager) GetUser(ctx context.Context, uid string) (*models.User, error) {
	err := um.connect(ctx)
	if err != nil {
		return nil, err
	}

	u, err := um.KeycloakGetUser(ctx, uid)

	if u == nil || err != nil {
		return nil, err
	}
	return UserToCloudy(u), err
}

// Placeholder if we want to use attributes defined outside of cloudy-keycloak
func (um *KeycloakUserManager) GetUserWithAttributes(ctx context.Context, uid string, attrs []string) (*models.User, error) {
	return um.GetUser(ctx, uid)
}

// Retrieves a specific user.
func (um *KeycloakUserManager) GetUserByEmail(ctx context.Context, email string, opts *cloudy.UserOptions) (*models.User, error) {
	err := um.connect(ctx)
	if err != nil {
		return nil, err
	}

	found, err := um.client.GetUsers(ctx, um.jwt.AccessToken, um.realm, gocloak.GetUsersParams{
		Email: &email,
	})
	if err != nil {
		return nil, err
	}
	if len((found)) == 0 {
		return nil, nil
	}
	return UserToCloudy(found[0]), nil
}

// NewUser creates a new user with the given information and returns the new user with any additional
// fields populated
func (um *KeycloakUserManager) NewUser(ctx context.Context, newUser *models.User) (*models.User, error) {
	err := um.connect(ctx)
	if err != nil {
		return nil, err
	}

	u := UserToKeycloak(newUser)
	uid, err := um.client.CreateUser(ctx, um.jwt.AccessToken, um.realm, *u)
	if uid != "" {
		newUser.UID = uid
	}
	return newUser, err
}

func (um *KeycloakUserManager) UpdateUser(ctx context.Context, usr *models.User) error {
	err := um.connect(ctx)
	if err != nil {
		return err
	}

	u := UserToKeycloak(usr)
	err = um.client.UpdateUser(ctx, um.jwt.AccessToken, um.realm, *u)
	return err
}

func (um *KeycloakUserManager) Enable(ctx context.Context, uid string) error {
	err := um.connect(ctx)
	if err != nil {
		return err
	}

	u := &gocloak.User{
		ID:      &uid,
		Enabled: cloudy.BoolP(true),
	}
	err = um.client.UpdateUser(ctx, um.jwt.AccessToken, um.realm, *u)
	return err
}

func (um *KeycloakUserManager) Disable(ctx context.Context, uid string) error {
	err := um.connect(ctx)
	if err != nil {
		return err
	}

	u := &gocloak.User{
		ID:      &uid,
		Enabled: cloudy.BoolP(false),
	}
	err = um.client.UpdateUser(ctx, um.jwt.AccessToken, um.realm, *u)
	return err
}

func (um *KeycloakUserManager) DeleteUser(ctx context.Context, uid string) error {
	err := um.connect(ctx)
	if err != nil {
		return err
	}

	err = um.client.DeleteUser(ctx, um.jwt.AccessToken, um.realm, uid)
	return err
}

func UserToCloudy(user *gocloak.User) *models.User {
	u := &models.User{
		UID:         str(user.ID, ""),
		Username:    str(user.Username, ""),
		FirstName:   str(user.FirstName, ""),
		LastName:    str(user.LastName, ""),
		Email:       str(user.Email, ""),
		Enabled:     *user.Enabled,
		DisplayName: first(user.Attributes, "DisplayName"),
	}

	u.Attributes = make(map[string]string)
	for _, attr := range AdditionalAttributes {
		if first(user.Attributes, attr.Name) != "" {
			u.Attributes[attr.Name] = first(user.Attributes, attr.Name)
		}
	}

	return u
}

func UserToKeycloak(u *models.User) *gocloak.User {
	attrs := make(map[string][]string)

	for _, attr := range AdditionalAttributes {
		val, ok := u.Attributes[attr.Name]
		if ok {
			attrs[attr.Name] = []string{val}
		}
	}

	user := &gocloak.User{
		ID:         &u.UID,
		Username:   &u.Username,
		Enabled:    &u.Enabled,
		FirstName:  &u.FirstName,
		LastName:   &u.LastName,
		Email:      &u.Email,
		Attributes: &attrs,
	}

	return user
}

func (um *KeycloakUserManager) KeycloakGetUser(ctx context.Context, uid string) (*gocloak.User, error) {
	err := um.connect(ctx)
	if err != nil {
		return nil, err
	}

	user, err := um.client.GetUserByID(ctx, um.jwt.AccessToken, um.realm, uid)
	if Is404(err) {
		return nil, nil
	}
	return user, err
}

func first(attr *map[string][]string, name string) string {
	if attr == nil {
		return ""
	}
	m := *attr
	items := m[name]
	if len(items) == 0 {
		return ""
	}
	return items[0]
}

func str(val *string, d string) string {
	if val == nil {
		return d
	}
	return *val
}

func Is404(err error) bool {
	var apiErr *gocloak.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == 404
	}
	return false
}

// Found in map components with key "org.keycloak.userprofile.UserProfileProvider"
// ID is "4c3baf89-84ee-42b5-a3ad-bdaea817b80e"
func (um *KeycloakUserManager) ParseProfileConfig(component *gocloak.Component) (*UserProfileConfig, error) {
	if component != nil {
		cfg := *component.ComponentConfig
		val := cfg["kc.user.profile.config"]
		if len(val) == 1 {
			var configs UserProfileConfig
			err := json.Unmarshal([]byte(val[0]), &configs)
			return &configs, err
		}
	}
	return nil, nil
}

func (um *KeycloakUserManager) FindUserProfileComponent(ctx context.Context) (*gocloak.Component, error) {
	return um.FindComponent(ctx, "declarative-user-profile")
}

func (um *KeycloakUserManager) FindComponent(ctx context.Context, providerId string) (*gocloak.Component, error) {
	err := um.connect(ctx)
	if err != nil {
		return nil, err
	}

	components, err := um.client.GetComponents(ctx, um.jwt.AccessToken, um.realm)
	if err != nil {
		return nil, err
	}
	for _, c := range components {
		if *c.ProviderID == providerId {
			return c, nil
		}
	}
	return nil, nil
}

func (um *KeycloakUserManager) SetUserPassword(ctx context.Context, userid string, pwd string) error {
	return um.client.SetPassword(ctx, um.jwt.AccessToken, userid, um.realm, pwd, false)
}

func (um *KeycloakUserManager) AddUserAttributes(ctx context.Context, attributes []*Attribute) error {
	component, err := um.FindUserProfileComponent(ctx)
	if err != nil {
		return err
	}
	if component == nil {
		return errors.New("No User Profile Found")
	}
	var config UserProfileConfig
	cfg := *component.ComponentConfig
	val := cfg["kc.user.profile.config"]
	if len(val) != 1 {
		return errors.New("Bad kc.user.profile.config")
	}
	err = json.Unmarshal([]byte(val[0]), &config)
	if err != nil {
		return err
	}

	for _, attr := range attributes {
		existing := config.FindAttributeByName(attr.Name)
		if existing != nil {
			continue
		}
		config.Attributes = append(config.Attributes, attr)
	}

	strCfg, err := json.Marshal(config)
	if err != nil {
		panic(err)
	}

	cfg["kc.user.profile.config"] = []string{string(strCfg)}
	component.ComponentConfig = &cfg

	err = um.client.UpdateComponent(ctx, um.jwt.AccessToken, um.realm, *component)
	return err
}
