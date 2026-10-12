#!/usr/bin/env bats
#
# Credential Proxy Lease Tests
#
# These tests verify that `fnox proxy run` takes rule secrets from lease
# credentials. No external services are required: a command lease prints
# credentials, and the child only inspects its own environment.

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

# Helper: a command lease that counts its runs and expires after $1 seconds.
create_lease_script() {
	cat >"$TEST_TEMP_DIR/lease.sh" <<SCRIPT
#!/usr/bin/env bash
count=\$(cat "$TEST_TEMP_DIR/count" 2>/dev/null || echo 0)
count=\$((count + 1))
echo "\$count" >"$TEST_TEMP_DIR/count"
epoch=\$((\$(date +%s) + $1))
expires=\$(date -u -d "@\$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "\$epoch" +%Y-%m-%dT%H:%M:%SZ)
echo "{\"credentials\":{\"GH_TOKEN\":\"gho-real-\$count\"},\"expires_at\":\"\$expires\",\"lease_id\":\"proxy-lease-\$count\"}"
SCRIPT
	chmod +x "$TEST_TEMP_DIR/lease.sh"
}

create_proxy_config() {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.github]
type = "command"
create_command = "$TEST_TEMP_DIR/lease.sh"

[proxy]
[[proxy.rules]]
secret = "GH_TOKEN"
domain = "api.github.com"
placeholder = "gho_placeholder"
EOF
}

@test "proxy run: a rule takes its secret from a command lease credential" {
	create_lease_script 3600
	create_proxy_config

	run "$FNOX_BIN" proxy run -- bash -c 'printf "token=%s\n" "$GH_TOKEN"'
	assert_success
	assert_output --partial "token=gho_placeholder"
	refute_output --partial "gho-real"

	run cat "$TEST_TEMP_DIR/count"
	assert_output "1"
}

@test "proxy run: records the lease and reuses it while it is valid" {
	create_lease_script 3600
	create_proxy_config

	run "$FNOX_BIN" proxy run -- true
	assert_success
	run "$FNOX_BIN" proxy run -- true
	assert_success

	run cat "$TEST_TEMP_DIR/count"
	assert_output "1"

	run "$FNOX_BIN" lease list --active
	assert_success
	assert_output --partial "proxy-lease-1"
}

@test "proxy run: renews an expiring lease while the command runs" {
	create_lease_script 4
	create_proxy_config

	run "$FNOX_BIN" proxy run -- bash -c 'sleep 5; printf "token=%s\n" "$GH_TOKEN"'
	assert_success
	assert_output --partial "token=gho_placeholder"
	refute_output --partial "gho-real"

	count=$(cat "$TEST_TEMP_DIR/count")
	[ "$count" -ge 2 ]
}

@test "proxy run: ambient lease credential names do not reach the child" {
	cat >"$TEST_TEMP_DIR/lease.sh" <<'SCRIPT'
#!/usr/bin/env bash
echo '{"credentials":{"GH_TOKEN":"gho-real","GH_EXTRA":"extra-real"},"lease_id":"proxy-lease-extra"}'
SCRIPT
	chmod +x "$TEST_TEMP_DIR/lease.sh"
	create_proxy_config

	export GH_EXTRA="ambient-extra"
	run "$FNOX_BIN" proxy run -- bash -c 'printf "extra=%s\n" "${GH_EXTRA:-unset}"'
	assert_success
	assert_output --partial "extra=unset"
}

@test "proxy run: a rule without a secret or lease fails" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[proxy]
[[proxy.rules]]
secret = "GH_TOKEN"
domain = "api.github.com"
EOF

	run "$FNOX_BIN" proxy run -- true
	assert_failure
	assert_output --partial "unknown secret 'GH_TOKEN'"
}

@test "proxy run: a command lease that does not provide the rule secret fails" {
	cat >"$TEST_TEMP_DIR/lease.sh" <<'SCRIPT'
#!/usr/bin/env bash
echo '{"credentials":{"OTHER_TOKEN":"other"},"lease_id":"proxy-lease-other"}'
SCRIPT
	chmod +x "$TEST_TEMP_DIR/lease.sh"
	create_proxy_config

	run "$FNOX_BIN" proxy run -- true
	assert_failure
	assert_output --partial "Proxy secret 'GH_TOKEN' did not resolve"
}

@test "proxy run: a lease credential equal to the placeholder is refused" {
	cat >"$TEST_TEMP_DIR/lease.sh" <<'SCRIPT'
#!/usr/bin/env bash
echo '{"credentials":{"GH_TOKEN":"gho_placeholder"},"lease_id":"proxy-lease-same"}'
SCRIPT
	chmod +x "$TEST_TEMP_DIR/lease.sh"
	create_proxy_config

	run "$FNOX_BIN" proxy run -- true
	assert_failure
	assert_output --partial "placeholder for 'GH_TOKEN' must differ from"
}

@test "proxy run: a renewed value equal to the placeholder is refused and the old value kept" {
	cat >"$TEST_TEMP_DIR/lease.sh" <<SCRIPT
#!/usr/bin/env bash
count=\$(cat "$TEST_TEMP_DIR/count" 2>/dev/null || echo 0)
count=\$((count + 1))
echo "\$count" >"$TEST_TEMP_DIR/count"
token="gho-real-1"
[ "\$count" -gt 1 ] && token="gho_placeholder"
epoch=\$((\$(date +%s) + 4))
expires=\$(date -u -d "@\$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "\$epoch" +%Y-%m-%dT%H:%M:%SZ)
echo "{\"credentials\":{\"GH_TOKEN\":\"\$token\"},\"expires_at\":\"\$expires\",\"lease_id\":\"proxy-lease-\$count\"}"
SCRIPT
	chmod +x "$TEST_TEMP_DIR/lease.sh"
	create_proxy_config

	run "$FNOX_BIN" proxy run -- bash -c 'sleep 3; printf "token=%s\n" "$GH_TOKEN"'
	assert_success
	assert_output --partial "token=gho_placeholder"
	assert_output --partial "Could not use renewed lease 'github'"
	assert_output --partial "must differ from the real value"
}
