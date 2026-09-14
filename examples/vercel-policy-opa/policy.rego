# Deterministic policy evaluated by @ai-sdk/policy-opa before the model's tool call runs.
# Composed with prompt-protection's provenance guard via composeToolApproval: deny wins.
package agent.call

default decision := "approved"

decision := "denied" if {
  input.toolName == "send_payment"
  not input.context.user.roles[_] == "admin"
}

decision := "user-approval" if {
  input.toolName == "send_payment"
  input.args.amount > 1000
}
