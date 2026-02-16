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

// ListAuthRoles creates a tool for listing roles in an auth method
func ListAuthRoles(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_auth_roles",
			mcp.WithDescription("List roles in a Vault auth method mount. Works for role-based auth methods like approle, jwt, oidc, kubernetes, aws, gcp, azure. For userpass use path_suffix='users', for ldap use path_suffix='groups' or 'users'."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("Auth method mount path (e.g., 'approle', 'jwt', 'kubernetes')")),
			mcp.WithString("path_suffix",
				mcp.DefaultString("role"),
				mcp.Description("Path suffix for listing roles. Defaults to 'role' (standard for most auth methods). Use 'users' for userpass, 'groups' or 'users' for ldap.")),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path (e.g., 'admin/'). Defaults to current namespace.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listAuthRolesHandler(ctx, req, logger)
		},
	}
}

func listAuthRolesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_auth_roles request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, ok := args["mount"].(string)
	if !ok || mount == "" {
		return mcp.NewToolResultError("mount is required"), nil
	}

	pathSuffix, _ := args["path_suffix"].(string)
	if pathSuffix == "" {
		pathSuffix = "role"
	}

	namespace, _ := args["namespace"].(string)

	logger.WithFields(log.Fields{
		"mount":       mount,
		"path_suffix": pathSuffix,
		"namespace":   namespace,
	}).Debug("Listing auth roles")

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

	listPath := fmt.Sprintf("auth/%s/%s", mount, pathSuffix)

	secret, err := nsClient.Logical().List(listPath)
	if err != nil {
		logger.WithError(err).Error("Failed to list auth roles")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list auth roles: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		logger.Debug("No roles found")
		return mcp.NewToolResultText(fmt.Sprintf("No roles found at auth/%s/%s", mount, pathSuffix)), nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No roles found at auth/%s/%s", mount, pathSuffix)), nil
	}

	roleNames := make([]string, 0, len(keys))
	for _, k := range keys {
		if name, ok := k.(string); ok {
			roleNames = append(roleNames, name)
		}
	}

	result := map[string]interface{}{
		"mount":       mount,
		"path_suffix": pathSuffix,
		"namespace":   namespace,
		"roles":       roleNames,
		"count":       len(roleNames),
	}

	jsonResult, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		logger.WithError(err).Error("Failed to marshal result")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	logger.WithField("count", len(roleNames)).Debug("Successfully listed auth roles")
	return mcp.NewToolResultText(string(jsonResult)), nil
}
