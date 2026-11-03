package authz

// Gateway actions (docs/gateway/PLAN.md 5.2, PROTOCOL.md 11-12).
//
// ProjectConnect is "may open a connection to a project's services through the gateway".
// It is registered into the role matrix from init() (like the Git Capsule actions) so AllActions and its
// decision-table tests keep their meaning; GatewayActions lists it.
//
// Coherence with what already exists: opening a database today is the SQL explorer (ProjectOps: deployer
// and admin), while changing who may reach it is ProjectNetwork (admin). Connecting is therefore
// viewer: no, deployer: yes, admin: yes. Exposing or closing a service (and its random port, and service
// tokens) is a network change and stays under ProjectNetwork (admin only).
const ProjectConnect Action = "project.connect"

// GatewayActions lists the gateway actions (tests and docs).
var GatewayActions = []Action{ProjectConnect}

func init() {
	matrix[RoleDeployer][ProjectConnect] = true
	matrix[RoleAdmin][ProjectConnect] = true
}
