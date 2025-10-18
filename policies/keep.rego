package keep

import future.keywords.if

default decision := "deny"

decision := "allow" if {
	valid_user
	input.device.trust_score >= 80
}

decision := "step-up" if {
	valid_user
	input.device.trust_score >= 50
	input.device.trust_score < 80
}

decision := "deny" if {
	input.device.trust_score < 50
}

decision := "deny" if {
	valid_user
	input.device.posture == "unknown"
}

decision := "deny" if {
	valid_user
	input.device.posture == "unregistered"
}

allow if decision == "allow"

valid_user if {
	input.user.email != ""
	input.user.email != null
}
