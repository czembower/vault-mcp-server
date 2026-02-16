// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ReadAuthRole creates a tool for reading role details from an auth method
func ReadAuthRole(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_auth_role",
			mcp.WithDescription("Read role configuration from a Vault auth method. Returns role details including policies, token settings, and auth method-specific configuration. Works for role-based auth methods like approle, jwt, oidc, kubernetes, aws, gcp, azure. For userpass use path_suffix='users', for ldap use path_suffix='groups' or 'users'."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("Auth method mount path (e.g., 'approle', 'jwt', 'kubernetes')")),
			mcp.WithString("role_name",
				mcp.Required(),
				mcp.Description("Name of the role to read (for userpass this is username, for ldap this is group/user name)")),
			mcp.WithString("path_suffix",
				mcp.DefaultString("role"),
				mcp.Description("Path suffix for reading roles. Defaults to 'role' (standard for most auth methods). Use 'users' for userpass, 'groups' or 'users' for ldap.")),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path (e.g., 'admin/'). Defaults to current namespace.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readAuthRoleHandler(ctx, req, logger)
		},
	}
}

func readAuthRoleHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_auth_role request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, ok := args["mount"].(string)
	if !ok || mount == "" {
		return mcp.NewToolResultError("mount is required"), nil
	}

	roleName, ok := args["role_name"].(string)
	if !ok || roleName == "" {
		return mcp.NewToolResultError("role_name is required"), nil
	}

	pathSuffix, _ := args["path_suffix"].(string)
	if pathSuffix == "" {
		pathSuffix = "role"
	}

	namespace, _ := args["namespace"].(string)

	logger.WithFields(log.Fields{
		"mount":       mount,
		"role_name":   roleName,
		"path_suffix": pathSuffix,
		"namespace":   namespace,
	}).Debug("Reading auth role")

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	nsClient := vault
	if namespace != "" {
		nsClient = vault.WithNamespace(namespace)
		logger.WithField("namespace", namespace).Debug("Using specified namespace")
	}

	readPath := fmt.Sprintf("auth/%s/%s/%s", mount, pathSuffix, roleName)

	secret, err := nsClient.Logical().Read(readPath)
	if err != nil {
		logger.WithError(err).Error("Failed to read auth role")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read auth role: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		logger.Debug("Role not found")
		return mcp.NewToolResultError(fmt.Sprintf("Role '%s' not found at auth/%s/%s", roleName, mount, pathSuffix)), nil
	}

	result := map[string]interface{}{
		"mount":       mount,
		"role_name":   roleName,
		"path_suffix": pathSuffix,
		"namespace":   namespace,
		"data":        secret.Data,
	}

	jsonResult, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		logger.WithError(err).Error("Failed to marshal result")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	logger.Debug("Successfully read auth role")
	return mcp.NewToolResultText(string(jsonResult)), nil
}
