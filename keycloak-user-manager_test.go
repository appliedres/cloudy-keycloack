package keycloak

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func startTestKeycloak(ctx context.Context) *cloudy.Environment {
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "quay.io/keycloak/keycloak:24.0.4",
			ExposedPorts: []string{"8080/tcp"},
			Env: map[string]string{
				"KEYCLOAK_ADMIN":          "adminuser",
				"KEYCLOAK_ADMIN_PASSWORD": "admin",
			},
			Cmd:        []string{"start-dev"},
			WaitingFor: wait.ForLog("Running the server in development mode"),
		},
		Started: true,
	})
	if err != nil {
		panic(err)
	}

	ip, err := container.Host(ctx)
	if err != nil {
		panic(err)
	}

	mappedPort, err := container.MappedPort(ctx, "8080")
	if err != nil {
		panic(err)
	}

	uri := fmt.Sprintf("http://%s:%s/", ip, mappedPort.Port())

	os.Setenv("KEYCLOAK_HOST", uri)
	os.Setenv("KEYCLOAK_USER", "adminuser")
	os.Setenv("KEYCLOAK_PWD", "admin")

	svc := cloudy.NewOsEnvironmentService()
	env := &cloudy.Environment{
		EnvSvc: svc,
	}
	return env
}

func TestUserManager(t *testing.T) {
	ctx := cloudy.StartContext()
	env := startTestKeycloak(ctx)
	um := NewKeycloakUserManagerFromEnv(ctx, env)

	created, err := um.NewUser(ctx, &models.User{
		UPN:       "test.user@arkloud.us",
		FirstName: "Test",
		LastName:  "User",
		Email:     "test.user@email.arkloud.us",
	})
	assert.NoError(t, err)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	assert.NotEmpty(t, created.ID)

	found, err := um.GetUser(ctx, created.ID)
	assert.NoError(t, err)
	assert.NotNil(t, found)
	assert.EqualValues(t, created, found)

	foundByEmail, err := um.GetUserByEmail(ctx, "test.user@email.arkloud.us", &cloudy.UserOptions{})
	assert.NoError(t, err)
	assert.NotNil(t, foundByEmail)

	err = um.DeleteUser(ctx, created.ID)
	assert.NoError(t, err)

	found2, err := um.GetUser(ctx, created.ID)
	assert.NoError(t, err)
	assert.Nil(t, found2)

	createdUsa, err := um.NewUser(ctx, &models.User{
		UPN:            "test.user-usa@arkloud.us",
		FirstName:      "Test",
		LastName:       "User-usa",
		Email:          "test.user-usa@email.arkloud.us",
		Citizenship:    "USA",
		Enabled:        true,
		AccountType:    "AccountType",
		Company:        "Company",
		ContractDate:   time.Now().Format(time.RFC3339),
		ContractNumber: "1234",
		Department:     "Department",
		DisplayName:    "DisplayName",
		JobTitle:       "JoBTitle",
		MobilePhone:    "999-999-9999",
		OfficePhone:    "111-999-9999",
		ProgramRole:    "ProgramRole",
		Organization:   "Organization",
		Project:        "Project",
	})
	assert.NoError(t, err)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	foundUsa, err := um.GetUser(ctx, createdUsa.ID)
	assert.NoError(t, err)
	assert.NotNil(t, foundUsa)
	assert.EqualValues(t, createdUsa, foundUsa)

	assert.True(t, createdUsa.Enabled)
	err = um.Disable(ctx, foundUsa.ID)
	assert.NoError(t, err)

	foundUsaDisabled, err := um.GetUser(ctx, createdUsa.ID)
	assert.NoError(t, err)
	assert.False(t, foundUsaDisabled.Enabled)

	err = um.Enable(ctx, foundUsa.ID)
	assert.NoError(t, err)

	foundUsaEnabled, err := um.GetUser(ctx, createdUsa.ID)
	assert.NoError(t, err)
	assert.True(t, foundUsaEnabled.Enabled)

	createdUsa.DisplayName = "UPDATED DISPLAY NAME"
	err = um.UpdateUser(ctx, createdUsa)
	assert.NoError(t, err)

	foundUsaUpdated, err := um.GetUser(ctx, createdUsa.ID)
	assert.NoError(t, err)
	assert.EqualValues(t, foundUsaUpdated, createdUsa)

	_, exists, err := um.ForceUserName(ctx, "not-there")
	assert.NoError(t, err)
	assert.False(t, exists)

	_, exists, err = um.ForceUserName(ctx, createdUsa.UPN)
	assert.NoError(t, err)
	assert.True(t, exists)

}

func TestUserManagerBulk(t *testing.T) {
	ctx := cloudy.StartContext()
	startContainer := time.Now()
	env := startTestKeycloak(ctx)
	elapsedContainer := time.Since(startContainer)

	um := NewKeycloakUserManagerFromEnv(ctx, env)

	start := time.Now()

	// Create 1000 users
	for i := range 1000 {
		created, err := um.NewUser(ctx, &models.User{
			UPN:       fmt.Sprintf("bulk.user-%v@arkloud.us", i),
			FirstName: "Test",
			LastName:  fmt.Sprintf("User-%v", i),
			Email:     fmt.Sprintf("test.user-%v@email.arkloud.us", i),
		})
		assert.NoError(t, err)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		assert.NotEmpty(t, created.ID)
	}
	elapsed := time.Since(start)

	// Now try to read them all
	startList := time.Now()
	all, _, err := um.ListUsers(ctx, nil, nil)
	elapsedList := time.Since(startList)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(all), 1000)

	fmt.Printf("Time To Start: %v\n", elapsedContainer)
	fmt.Printf("Time To Add: %v\n", elapsed)
	fmt.Printf("Time To List: %v\n", elapsedList)
}

// func TestKeycloakConnection(t *testing.T) {
// 	// Docker
// 	// docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:24.0.4 start-dev

// 	// Setup Keycloak to the point that it is "ready" for some tests....
// 	ctx := cloudy.StartContext()
// 	env := startTestKeycloak(ctx)
// 	host := env.Force("KEYCLOAK_HOST")
// 	adminUser := env.Force("KEYCLOAK_USER")
// 	pwd := env.Force("KEYCLOAK_PWD")
// 	realm := env.Default("KEYCLOAK_REALM", "master")

// 	// client := gocloak.NewClient("http://localhost:8080/")
// 	client := gocloak.NewClient(host)
// 	// token, err := client.LoginAdmin(ctx, "admin", "admin", "master")
// 	token, err := client.LoginAdmin(ctx, adminUser, pwd, realm)
// 	if err != nil {
// 		panic("Something wrong with the credentials or url")
// 	}

// 	user := gocloak.User{
// 		FirstName: gocloak.StringP("Bob"),
// 		LastName:  gocloak.StringP("Uncle"),
// 		Email:     gocloak.StringP("something@really.wrong"),
// 		Enabled:   gocloak.BoolP(true),
// 		Username:  gocloak.StringP("CoolGuy"),
// 	}

// 	_, err = client.CreateUser(ctx, token.AccessToken, "master", user)
// 	if err != nil {
// 		panic(err)
// 	}
// }
