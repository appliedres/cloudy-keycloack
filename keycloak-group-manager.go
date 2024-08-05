package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
)

func init() {
	cloudy.GroupProviders.Register(Keycloak, &KeycloakGroupManagerFactory{})
}

type KeycloakGroupManagerFactory struct{}

func (umf *KeycloakGroupManagerFactory) Create(cfg interface{}) (cloudy.GroupManager, error) {
	return cfg.(*KeycloakGroupManager), nil
}

func (umf *KeycloakGroupManagerFactory) FromEnv(env *cloudy.Environment) (interface{}, error) {
	cfg := NewKeycloakUserManagerFromEnv(context.Background(), env)
	return cfg, nil
}

type KeycloakGroupManager struct {
	address string
	user    string
	pwd     string
	realm   string
	client  *gocloak.GoCloak
	jwt     *gocloak.JWT
}

func NewKeycloak(address string, user string, pwd string, realm string) *KeycloakGroupManager {
	return &KeycloakGroupManager{
		address: address,
		user:    user,
		pwd:     pwd,
		realm:   realm,
	}
}

func NewGroupManagerFromEnv(ctx context.Context, env *cloudy.Environment) *KeycloakGroupManager {
	cfg := &KeycloakGroupManager{}
	cfg.address = env.Force("KEYCLOAK_HOST")
	cfg.user = env.Force("KEYCLOAK_USER")
	cfg.pwd = env.Force("KEYCLOAK_PWD")
	cfg.realm = env.Default("KEYCLOAK_REALM", "master")
	return cfg
}

func (um *KeycloakGroupManager) connect() error {
	//FIXME : CHECK EXPIRED
	if um.jwt != nil {
		return nil
	}

	client := gocloak.NewClient(um.address)
	ctx := context.Background()
	token, err := client.LoginAdmin(ctx, um.user, um.pwd, um.realm)
	if err != nil {
		return err
	}
	um.jwt = token
	um.client = client
	return nil
}

// List all the groups available
func (gm *KeycloakGroupManager) ListGroups(ctx context.Context, filter string, attrs []string) (*[]models.Group, error) {
	err := gm.connect()
	if err != nil {
		return nil, err
	}

	found, err := gm.client.GetGroups(ctx, gm.jwt.AccessToken, gm.realm, gocloak.GetGroupsParams{})
	if err != nil {
		return nil, err
	}
	rtn := make([]models.Group, len(found))
	for i, g := range found {
		rtn[i] = *GroupToCloudy(g)
	}
	return &rtn, nil
}

// Get a specific group by id
func (gm *KeycloakGroupManager) GetGroup(ctx context.Context, id string) (*models.Group, error) {
	err := gm.connect()
	if err != nil {
		return nil, err
	}
	found, err := gm.client.GetGroup(ctx, gm.jwt.AccessToken, gm.realm, id)
	if err != nil {
		return nil, err
	}

	return GroupToCloudy(found), nil
}

// Get a group id from name
func (gm *KeycloakGroupManager) GetGroupId(ctx context.Context, name string) (string, error) {
	err := gm.connect()
	if err != nil {
		return "", err
	}
	found, err := gm.client.GetGroups(ctx, gm.jwt.AccessToken, gm.realm, gocloak.GetGroupsParams{
		Exact: cloudy.BoolP(true),
		Q:     &name,
	})
	if err != nil {
		return "", err
	}
	if len(found) == 0 {
		return "", nil
	}
	return *found[0].ID, nil
}

// Get all the groups for a single user
func (gm *KeycloakGroupManager) GetUserGroups(ctx context.Context, uid string) ([]*models.Group, error) {
	err := gm.connect()
	if err != nil {
		return nil, err
	}
	found, err := gm.client.GetUserGroups(ctx, gm.jwt.AccessToken, gm.realm, uid, gocloak.GetGroupsParams{})
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, nil
	}
	rtn := make([]*models.Group, len(found))
	for i, g := range found {
		rtn[i] = GroupToCloudy(g)
	}
	return rtn, nil
}

// Create a new Group
func (gm *KeycloakGroupManager) NewGroup(ctx context.Context, grp *models.Group) (*models.Group, error) {
	err := gm.connect()
	if err != nil {
		return nil, err
	}
	g := GroupToKeycloak(grp)
	id, err := gm.client.CreateGroup(ctx, gm.jwt.AccessToken, gm.realm, *g)
	if id != "" {
		grp.ID = id
	}
	return grp, err
}

// Update a group. This is generally just the name of the group.
func (gm *KeycloakGroupManager) UpdateGroup(ctx context.Context, grp *models.Group) (bool, error) {
	err := gm.connect()
	if err != nil {
		return false, err
	}
	g := GroupToKeycloak(grp)
	err = gm.client.UpdateGroup(ctx, gm.jwt.AccessToken, gm.realm, *g)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Get all the members of a group. This returns partial users only,
// typically just the user id, name and email fields
func (gm *KeycloakGroupManager) GetGroupMembers(ctx context.Context, grpId string) ([]*models.User, error) {
	err := gm.connect()
	if err != nil {
		return nil, err
	}
	found, err := gm.client.GetGroupMembers(ctx, gm.jwt.AccessToken, gm.realm, grpId, gocloak.GetGroupsParams{})
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, nil
	}
	rtn := make([]*models.User, len(found))
	for i, u := range found {
		rtn[i] = UserToCloudy(u)
	}
	return rtn, nil
}

// Remove members from a group
func (gm *KeycloakGroupManager) RemoveMembers(ctx context.Context, groupId string, userIds []string) error {
	err := gm.connect()
	if err != nil {
		return err
	}
	merr := cloudy.MultiError()
	for _, userId := range userIds {
		err := gm.client.DeleteUserFromGroup(ctx, gm.jwt.AccessToken, gm.realm, userId, groupId)
		if err != nil {
			merr.Append(err)
		}
	}
	return merr.AsErr()
}

// Add member(s) to a group
func (gm *KeycloakGroupManager) AddMembers(ctx context.Context, groupId string, userIds []string) error {
	err := gm.connect()
	if err != nil {
		return err
	}
	merr := cloudy.MultiError()
	for _, userId := range userIds {
		err := gm.client.AddUserToGroup(ctx, gm.jwt.AccessToken, gm.realm, userId, groupId)
		if err != nil {
			merr.Append(err)
		}
	}
	return merr.AsErr()
}

func (gm *KeycloakGroupManager) DeleteGroup(ctx context.Context, groupId string) error {
	err := gm.connect()
	if err != nil {
		return err
	}
	err = gm.client.DeleteGroup(ctx, gm.jwt.AccessToken, gm.realm, groupId)
	return err
}

func GroupToCloudy(g *gocloak.Group) *models.Group {
	group := &models.Group{
		ID:     *g.ID,
		Name:   *g.Name,
		Source: "Keycloak",
		Type:   "security",
		Extra:  g,
	}
	return group
}

func GroupToKeycloak(g *models.Group) *gocloak.Group {
	group := &gocloak.Group{}
	if g.ID != "" {
		group.ID = &g.ID
	}
	if g.Name != "" {
		group.Name = &g.Name
	}
	return group
}
