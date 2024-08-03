package keycloak

import (
	"testing"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/stretchr/testify/assert"
)

func TestGroupManager(t *testing.T) {
	ctx := cloudy.StartContext()
	env := startTestKeycloak(ctx)
	gm := NewGroupManagerFromEnv(ctx, env)

	groups, err := gm.ListGroups(ctx, "", nil)
	assert.NoError(t, err)
	assert.Empty(t, groups)

	group := &models.Group{
		Name: "My Test Group",
	}
	created, err := gm.NewGroup(ctx, group)
	assert.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.NotEmpty(t, group.ID)

	groups, err = gm.ListGroups(ctx, "", nil)
	assert.NoError(t, err)
	assert.Equal(t, len(*groups), 1)

	groupId, err := gm.GetGroupId(ctx, group.Name)
	assert.NoError(t, err)
	assert.Equal(t, groupId, group.ID)

	found, err := gm.GetGroup(ctx, groupId)
	assert.NoError(t, err)
	assert.Equal(t, found.ID, groupId)

	group.Name = "Updated"
	updated, err := gm.UpdateGroup(ctx, group)
	assert.NoError(t, err)
	assert.True(t, updated)

	foundUpdated, err := gm.GetGroup(ctx, groupId)
	assert.NoError(t, err)
	assert.Equal(t, foundUpdated.Name, group.Name)

	err = gm.DeleteGroup(ctx, groupId)
	assert.NoError(t, err)

	groups, err = gm.ListGroups(ctx, "", nil)
	assert.NoError(t, err)
	assert.Empty(t, groups)

}

func TestGroupManagerMembers(t *testing.T) {
	ctx := cloudy.StartContext()
	env := startTestKeycloak(ctx)
	gm := NewGroupManagerFromEnv(ctx, env)
	um := NewKeycloakUserManagerFromEnv(ctx, env)

	groups, err := gm.ListGroups(ctx, "", nil)
	assert.NoError(t, err)
	assert.Empty(t, groups)

	group := &models.Group{
		Name: "My Test Group",
	}
	created, err := gm.NewGroup(ctx, group)
	assert.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.NotEmpty(t, group.ID)

	user, err := um.NewUser(ctx, &models.User{
		Username:  "test-group-user",
		FirstName: "Test",
		LastName:  "group user",
		Email:     "test-group-user@nowhere.aaa",
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, user.UID)

	userGroups, err := gm.GetUserGroups(ctx, user.UID)
	assert.NoError(t, err)
	assert.Empty(t, userGroups)

	members, err := gm.GetGroupMembers(ctx, group.ID)
	assert.NoError(t, err)
	assert.Empty(t, members)

	err = gm.AddMembers(ctx, group.ID, []string{user.UID})
	assert.NoError(t, err)

	members, err = gm.GetGroupMembers(ctx, group.ID)
	assert.NoError(t, err)
	assert.NotEmpty(t, members)

	userGroups, err = gm.GetUserGroups(ctx, user.UID)
	assert.NoError(t, err)
	assert.NotEmpty(t, userGroups)

	err = gm.RemoveMembers(ctx, group.ID, []string{user.UID})
	assert.NoError(t, err)

	members, err = gm.GetGroupMembers(ctx, group.ID)
	assert.NoError(t, err)
	assert.Empty(t, members)

	userGroups, err = gm.GetUserGroups(ctx, user.UID)
	assert.NoError(t, err)
	assert.Empty(t, userGroups)

}
