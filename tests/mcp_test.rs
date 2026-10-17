use rev_core::mcp::McpServer;

#[test]
fn test_mcp_tool_registry_includes_v2_tools() {
    let tools = McpServer::get_tools();

    let tool_names: Vec<String> = tools.iter().map(|t| t.name.clone()).collect();
    assert!(tool_names.contains(&"audit_hardening".to_string()));
    assert!(tool_names.contains(&"lift_pseudocode".to_string()));
    assert!(tool_names.contains(&"demangle_symbol".to_string()));
    assert!(tool_names.contains(&"inspect_binary".to_string()));
    assert!(tool_names.contains(&"generate_cfg".to_string()));
}
