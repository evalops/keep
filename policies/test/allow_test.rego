package keep_test

import future.keywords

test_allow_healthy_device {
	input := {
		"user": {"email": "alice@example.com"},
		"device": {"posture": "healthy"},
		"client_ip": "192.168.1.10",
	}
	result := data.keep.decision with input as input
	result == "allow"
}

test_step_up_quarantined {
	input := {
		"user": {"email": "alice@example.com"},
		"device": {"posture": "quarantined"},
	}
	result := data.keep.decision with input as input
	result == "step-up"
}

test_deny_missing_user {
	input := {
		"user": {"email": ""},
		"device": {"posture": "healthy"},
	}
	result := data.keep.decision with input as input
	result == "deny"
}
