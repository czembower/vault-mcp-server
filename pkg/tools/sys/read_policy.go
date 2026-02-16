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

type PolicyDetail struct {
	Name   string `json:"name"`   // Name of the policy
	Policy string `json:"policy"` // The policy rules in HCL format
}

// ReadPolicy creates a tool for reading a specific Vault policy
func ReadPolicy(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_policy",
			mcp.WithDescription("Read the contents of a specific Vault policy. Returns the policy rules in HCL format."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("The name of the policy to read (e.g., 'default', 'admin-policy').")),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path where the policy exists (e.g., 'admin/' or empty for root). Defaults to current namespace.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readPolicyHandler(ctx, req, logger)
		},
	}
}

func readPolicyHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_policy request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	policyName, ok := args["name"].(string)
	if !ok || policyName == "" {
		return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
	}

	namespace, _ := args["namespace"].(string)

	logger.WithFields(log.Fields{
		"policy":    policyName,
		"namespace": namespace,
	}).Debug("Reading policy")

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

	// Read policy from Vault
	policyContent, err := nsClient.Sys().GetPolicy(policyName)
	if err != nil {
		logger.WithError(err).Error("Failed to read policy")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read policy '%s': %v", policyName, err)), nil
	}

	if policyContent == "" {
		logger.WithField("policy", policyName).Warn("Policy not found or empty")
		return mcp.NewToolResultError(fmt.Sprintf("Policy '%s' not found", policyName)), nil
	}

	result := &PolicyDetail{
		Name:   policyName,
		Policy: policyContent,
	}

	// Marshal the struct to JSON
	jsonData, err := json.Marshal(result)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal policy to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithField("policy", policyName).Debug("Successfully read policy")
	return mcp.NewToolResultText(string(jsonData)), nil
}
