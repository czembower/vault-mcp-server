// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package sys

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

type Policy struct {
	Name string `json:"name"` // Name of the policy
}

// ListPolicies creates a tool for listing Vault policies
func ListPolicies(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_policies",
			mcp.WithDescription("List all policies configured in Vault. Returns the names of all policies available in the specified namespace."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path to list policies from (e.g., 'admin/' or empty for root). Defaults to current namespace.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listPoliciesHandler(ctx, req, logger)
		},
	}
}

func listPoliciesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_policies request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	namespace, _ := args["namespace"].(string)

	logger.WithFields(log.Fields{
		"namespace": namespace,
	}).Debug("Listing policies")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Create a new client instance with the specified namespace if provided
	nsClient := vault
	if namespace != "" {
		nsClient = vault.WithNamespace(namespace)
		logger.WithField("namespace", namespace).Debug("Using specified namespace")
	}

	// List policies from Vault using sys/policies/acl
	policies, err := nsClient.Sys().ListPolicies()
	if err != nil {
		logger.WithError(err).Error("Failed to list policies")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list policies: %v", err)), nil
	}

	var results []*Policy
	for _, policyName := range policies {
		policy := &Policy{
			Name: policyName,
		}
		results = append(results, policy)
	}

	// Marshal the struct to JSON
	jsonData, err := json.Marshal(results)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal policies to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithField("policy_count", len(results)).Debug("Successfully listed policies")
	return mcp.NewToolResultText(string(jsonData)), nil
}
