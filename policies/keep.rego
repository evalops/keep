package keep

default decision := "deny"

allow := decision == "allow"

decision := "allow" {
	valid_user
	valid_device
}

decision := "step-up" {
	valid_user
	input.device.posture == "quarantined"
}

valid_user {
	input.user.email != ""
}

valid_device {
	input.device.posture == "healthy"
}
