package keep_test

import future.keywords.if

test_allow_healthy_device if {
	input_data := {
		"user": {"email": "alice@example.com"},
		"device": {"posture": "healthy", "trust_score": 90},
		"client_ip": "192.168.1.10",
	}
	result := data.keep.decision with input as input_data
	result == "allow"
}

test_step_up_quarantined if {
	input_data := {
		"user": {"email": "alice@example.com"},
		"device": {"posture": "quarantined", "trust_score": 65},
	}
	result := data.keep.decision with input as input_data
	result == "step-up"
}

test_deny_missing_user if {
	input_data := {
		"user": {"email": ""},
		"device": {"posture": "healthy", "trust_score": 85},
	}
	result := data.keep.decision with input as input_data
	result == "deny"
}
