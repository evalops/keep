package keep

default decision := "deny"

# High trust score - allow access
decision := "allow" {
	valid_user
	input.device.trust_score >= 80
}

# Medium trust score - require step-up authentication  
decision := "step-up" {
	valid_user
	input.device.trust_score >= 50
	input.device.trust_score < 80
}

# Low trust score - deny access
decision := "deny" {
	input.device.trust_score < 50
}

# Special case: unknown or unregistered devices
decision := "deny" {
	valid_user
	input.device.posture == "unknown"
}

decision := "deny" {
	valid_user
	input.device.posture == "unregistered"
}

# Backward compatibility
allow {
	decision == "allow"
}

valid_user {
	input.user.email != ""
	input.user.email != null
}
