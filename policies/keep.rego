package keep.authz

import future.keywords.if
import future.keywords.in

# Default deny
default decision := "deny"

# Helper: Check if device is compliant
device_compliant if {
	input.device.posture == "healthy"
	input.device.trust_score >= 70
	input.device.compliant == true
}

# Helper: Check if device meets baseline security
device_baseline_security if {
	input.device.attributes.encrypted == true
	input.device.attributes.firewall == true
	input.device.attributes.updates_current == true
}

# Helper: Check if device has EDR
device_has_edr if {
	input.device.attributes.edr_healthy == true
}

# Helper: Check if device data is fresh
device_data_fresh if {
	input.device.time_since_last_seen_minutes < 10
}

# Helper: Check if user is valid
valid_user if {
	input.user.email != ""
	input.user.email != null
}

# Rule: Admin access requires highest security
allow_admin_access if {
	"admin" in input.user.groups
	device_compliant
	device_baseline_security
	device_has_edr
	device_data_fresh
	input.device.trust_score >= 90
}

# Rule: Engineering access requires compliant device
allow_engineering_access if {
	"engineering" in input.user.groups
	device_compliant
	device_baseline_security
	device_data_fresh
}

# Rule: Contractor access requires elevated security + time restrictions
allow_contractor_access if {
	"contractor" in input.user.groups
	device_compliant
	device_baseline_security
	device_has_edr
	device_data_fresh
	input.device.trust_score >= 80
	
	# Time restrictions: 9am-6pm PT, Mon-Fri
	input.context.hour_of_day >= 9
	input.context.hour_of_day < 18
	input.context.day_of_week in ["monday", "tuesday", "wednesday", "thursday", "friday"]
}

# Rule: Step-up MFA for degraded devices
require_step_up if {
	valid_user
	device_data_fresh
	input.device.trust_score >= 50
	input.device.trust_score < 70
}

# Rule: Deny stale devices
deny_stale_device if {
	input.device.posture == "unknown"
}

# Rule: Deny unregistered devices
deny_unregistered if {
	input.device.posture == "unregistered"
}

# Rule: Deny non-encrypted devices
deny_unencrypted if {
	input.device.attributes.encrypted == false
}

# Rule: Deny devices without firewall
deny_no_firewall if {
	input.device.attributes.firewall == false
}

# Rule: Deny devices with many pending updates
deny_outdated if {
	input.device.attributes.updates_outstanding > 20
}

# Final decision logic
decision := "allow" if {
	valid_user
	allow_admin_access
}

decision := "allow" if {
	valid_user
	allow_engineering_access
}

decision := "allow" if {
	valid_user
	allow_contractor_access
}

decision := "step-up" if {
	require_step_up
	not deny_stale_device
	not deny_unregistered
	not deny_unencrypted
	not deny_no_firewall
}

decision := "deny" if {
	deny_stale_device
}

decision := "deny" if {
	deny_unregistered
}

decision := "deny" if {
	deny_unencrypted
}

decision := "deny" if {
	deny_no_firewall
}

decision := "deny" if {
	deny_outdated
}

# Metadata for decision logging
metadata := {
	"matched_rules": [rule | allow_rules[rule]],
	"deny_reasons": [reason | deny_rules[reason]],
	"trust_score": input.device.trust_score,
	"user_groups": input.user.groups,
	"device_posture": input.device.posture
}

allow_rules := {
	"admin_access": allow_admin_access,
	"engineering_access": allow_engineering_access,
	"contractor_access": allow_contractor_access
}

deny_rules := {
	"stale_device": deny_stale_device,
	"unregistered": deny_unregistered,
	"unencrypted": deny_unencrypted,
	"no_firewall": deny_no_firewall,
	"outdated": deny_outdated
}

# Legacy allow for backward compatibility
allow if decision == "allow"
