package keep.authz_test

import future.keywords.if

test_allow_admin_compliant_device if {
	input_data := {
		"user": {
			"email": "alice@example.com",
			"groups": ["admin"]
		},
		"device": {
			"posture": "healthy", 
			"trust_score": 95,
			"compliant": true,
			"time_since_last_seen_minutes": 2,
			"attributes": {
				"encrypted": true,
				"firewall": true,
				"updates_current": true,
				"edr_healthy": true
			}
		},
		"context": {
			"hour_of_day": 14,
			"day_of_week": "tuesday"
		}
	}
	result := data.keep.authz.decision with input as input_data
	result == "allow"
}

test_allow_engineering_compliant_device if {
	input_data := {
		"user": {
			"email": "bob@example.com",
			"groups": ["engineering"]
		},
		"device": {
			"posture": "healthy", 
			"trust_score": 85,
			"compliant": true,
			"time_since_last_seen_minutes": 5,
			"attributes": {
				"encrypted": true,
				"firewall": true,
				"updates_current": true,
				"edr_healthy": false
			}
		},
		"context": {
			"hour_of_day": 10,
			"day_of_week": "monday"
		}
	}
	result := data.keep.authz.decision with input as input_data
	result == "allow"
}

test_step_up_degraded_device if {
	input_data := {
		"user": {
			"email": "charlie@example.com",
			"groups": ["engineering"]
		},
		"device": {
			"posture": "degraded", 
			"trust_score": 65,
			"compliant": false,
			"time_since_last_seen_minutes": 5,
			"attributes": {
				"encrypted": true,
				"firewall": true,
				"updates_current": false
			}
		},
		"context": {
			"hour_of_day": 11,
			"day_of_week": "wednesday"
		}
	}
	result := data.keep.authz.decision with input as input_data
	result == "step-up"
}

test_deny_unencrypted_device if {
	input_data := {
		"user": {
			"email": "dave@example.com",
			"groups": ["engineering"]
		},
		"device": {
			"posture": "healthy", 
			"trust_score": 90,
			"compliant": true,
			"time_since_last_seen_minutes": 2,
			"attributes": {
				"encrypted": false,
				"firewall": true,
				"updates_current": true
			}
		},
		"context": {
			"hour_of_day": 15,
			"day_of_week": "friday"
		}
	}
	result := data.keep.authz.decision with input as input_data
	result == "deny"
}

test_deny_contractor_outside_hours if {
	input_data := {
		"user": {
			"email": "contractor@example.com",
			"groups": ["contractor"]
		},
		"device": {
			"posture": "healthy", 
			"trust_score": 85,
			"compliant": true,
			"time_since_last_seen_minutes": 3,
			"attributes": {
				"encrypted": true,
				"firewall": true,
				"updates_current": true,
				"edr_healthy": true
			}
		},
		"context": {
			"hour_of_day": 20,  # 8pm - outside allowed hours
			"day_of_week": "tuesday"
		}
	}
	result := data.keep.authz.decision with input as input_data
	result == "deny"
}

test_deny_stale_device if {
	input_data := {
		"user": {
			"email": "eve@example.com",
			"groups": ["engineering"]
		},
		"device": {
			"posture": "unknown",
			"trust_score": 0,
			"compliant": false,
			"attributes": {}
		},
		"context": {
			"hour_of_day": 12,
			"day_of_week": "thursday"
		}
	}
	result := data.keep.authz.decision with input as input_data
	result == "deny"
}
