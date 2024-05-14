package keycloak

const (
	AttributePermissionAdmin = "admin"
	AttributePermissionUser  = "admin"
)

type UserProfileConfig struct {
	Attributes []*Attribute      `json:"attributes"`
	Groups     []*AttributeGroup `json:"groups"`
}

type AttributeGroup struct {
	Name               string `json:"name"`
	DisplayHeader      string `json:"displayHeader"`
	DisplayDescription string `json:"displayDescription"`
}

type Validation struct {
	Length *ValidationLength `json:"length"`
	// UsernameProhibitedCharacters struct{}          `json:"username-prohibited-characters"`
	// UPUsernameNotIDNHomograph    struct{}          `json:"up-username-not-idn-homograph"`
}

type ValidationLength struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

type Permissions struct {
	View []string `json:"view"`
	Edit []string `json:"edit"`
}

type Attribute struct {
	Name        string      `json:"name"`
	DisplayName string      `json:"displayName"`
	Validations Validation  `json:"validations"`
	Permissions Permissions `json:"permissions"`
	Multivalued bool        `json:"multivalued"`
}

var AttrUsername = &Attribute{
	Name:        "username",
	DisplayName: "${username}",
	Validations: Validation{
		&ValidationLength{Min: 3, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrEmail = &Attribute{
	Name:        "email",
	DisplayName: "${email}",
	Validations: Validation{
		&ValidationLength{Min: 3, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrFirstName = &Attribute{
	Name:        "firstName",
	DisplayName: "${firstName}",
	Validations: Validation{
		&ValidationLength{Min: 3, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrLastName = &Attribute{
	Name:        "lastName",
	DisplayName: "${lastName}",
	Validations: Validation{
		&ValidationLength{Min: 3, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var DefaultAttributes = []*Attribute{
	AttrUsername, AttrEmail, AttrFirstName, AttrLastName,
}

func (cfg *UserProfileConfig) FindAttributeByName(name string) *Attribute {
	for _, existing := range cfg.Attributes {
		if existing.Name == name {
			return existing
		}
	}
	return nil
}

var AttrAccountType = &Attribute{
	Name:        "AccountType",
	DisplayName: "AccountType",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}
var AttrCitizenship = &Attribute{
	Name:        "Citizenship",
	DisplayName: "Citizenship",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrCompany = &Attribute{
	Name:        "Company",
	DisplayName: "Company",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrContractDate = &Attribute{
	Name:        "ContractDate",
	DisplayName: "ContractDate",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrContractNumber = &Attribute{
	Name:        "ContractNumber",
	DisplayName: "ContractNumber",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrDepartment = &Attribute{
	Name:        "Department",
	DisplayName: "Department",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrDisplayName = &Attribute{
	Name:        "DisplayName",
	DisplayName: "DisplayName",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrMobilePhone = &Attribute{
	Name:        "MobilePhone",
	DisplayName: "MobilePhone",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrOfficePhone = &Attribute{
	Name:        "OfficePhone",
	DisplayName: "OfficePhone",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrOrganization = &Attribute{
	Name:        "Organization",
	DisplayName: "Organization",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrJobTitle = &Attribute{
	Name:        "JobTitle",
	DisplayName: "JobTitle",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrProgramRole = &Attribute{
	Name:        "ProgramRole",
	DisplayName: "ProgramRole",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}

var AttrProject = &Attribute{
	Name:        "Project",
	DisplayName: "Project",
	Validations: Validation{
		&ValidationLength{Min: 1, Max: 255},
	},
	Permissions: Permissions{
		View: []string{AttributePermissionAdmin, AttributePermissionUser},
		Edit: []string{AttributePermissionAdmin, AttributePermissionUser},
	},
	Multivalued: false,
}
var AdditionalAttributes = []*Attribute{
	AttrAccountType,
	AttrCitizenship,
	AttrCompany,
	AttrContractDate,
	AttrContractNumber,
	AttrDepartment,
	AttrDisplayName,
	AttrMobilePhone,
	AttrOfficePhone,
	AttrOrganization,
	AttrJobTitle,
	AttrProgramRole,
	AttrProject,
}
