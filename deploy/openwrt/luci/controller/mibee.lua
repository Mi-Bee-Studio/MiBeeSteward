-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- MiBee Steward LuCI integration: registers the router-native entry under
-- 服务 → MiBee Steward (status view + settings forms). Deliberately a
-- classic Lua controller with plain templates — works across 22.03/23.05/
-- 24.05+ LuCI (the dispatcher still scans this path) with NO luci-compat /
-- CBI dependency. All privileged work happens in
-- /usr/lib/mibee/luci-helper.sh (single audited surface); this controller
-- only validates input, hands over, and redirects back with a message code.

module("luci.controller.mibee", package.seeall)

local HELPER = "/usr/lib/mibee/luci-helper.sh"

function index()
    -- Hide the whole tree when the binary isn't installed (e.g. ipk removed
    -- but the controller file survived).
    local fs = require "nixio.fs"
    if not fs.access("/usr/bin/mibee-steward") then
        return
    end
    entry({"admin", "services", "mibee"}, firstchild(), "MiBee Steward", 60).dependent = false
    entry({"admin", "services", "mibee", "status"}, template("mibee/status"), "状态 Status", 10)
    entry({"admin", "services", "mibee", "settings"}, template("mibee/settings"), "设置 Settings", 20)
    entry({"admin", "services", "mibee", "apply"}, call("action_apply")).leaf = true
end

-- session_token resolves the CSRF token across luci-base generations: newer
-- builds expose luci.sys.token, older ones only dispatcher context.authtoken.
-- nil = this build has no token infrastructure; the check is skipped (the
-- pages still sit behind LuCI's root login).
local function session_token()
    local ok, v = pcall(function() return require("luci.sys").token end)
    if ok and type(v) == "string" then return v end
    if ok and type(v) == "function" then
        local ok2, v2 = pcall(v)
        if ok2 and type(v2) == "string" then return v2 end
    end
    local ctx = require("luci.dispatcher").context
    if ctx and ctx.authtoken then return ctx.authtoken end
    return nil
end

-- helper_call runs luci-helper.sh and returns its exit code. Deliberately
-- plain io.popen, NOT luci.sys.call: on the ucode-era LuCI (24.10's
-- luci-lua-runtime bridge) sys.call() inside a bridged Lua controller kills
-- the HTTP response — uhttpd answers 502 "Bad Gateway: the process did not
-- produce any response" while the operation itself succeeds (field-found on
-- iStoreOS 24.10.8). io.popen / os.execute are plain Lua C-API calls and
-- provably survive the bridge (nixio.fs and luci.http.write do too).
local function helper_call(args)
    local fh = io.popen(HELPER .. " " .. args .. '; echo " rc=$?"')
    if not fh then return -1 end
    local out = fh:read("*a") or ""
    fh:close()
    return tonumber(out:match("rc=(-?%d+)%s*$")) or -1
end

function action_apply()
    local http = require "luci.http"
    local dispatcher = require "luci.dispatcher"

    local expect = session_token()
    if expect and http.formvalue("token") ~= expect then
        http.status(403, "Forbidden")
        http.prepare_content("text/plain")
        http.write("invalid token")
        return
    end

    local act = http.formvalue("act")
    local msg = "noop"

    if act == "restart" then
        local rc = helper_call("restart")
        msg = (rc == 0) and "restart_ok" or "restart_fail"

    elseif act == "enabled" then
        local val = (http.formvalue("enabled") == "1") and "1" or "0"
        local rc = helper_call(string.format("set-enabled %s", val))
        msg = (rc == 0) and "enabled_ok" or "enabled_fail"

    elseif act == "port" then
        local port = tonumber(http.formvalue("port") or "")
        if port and port == math.floor(port) and port >= 1 and port <= 65535 then
            local rc = helper_call(string.format("set-port %d", port))
            msg = (rc == 0) and "port_ok" or "port_fail"
        else
            msg = "port_invalid"
        end

    elseif act == "password" then
        local pw = http.formvalue("password") or ""
        local pw2 = http.formvalue("password2") or ""
        if pw == "" then
            msg = "pw_empty"
        elseif pw ~= pw2 then
            msg = "pw_mismatch"
        else
            -- The password NEVER touches a command line: it is handed over
            -- through a 0600 tmpfs file that the helper consumes and deletes.
            local fs = require "nixio.fs"
            local pwfile = string.format("/tmp/.mibee-pw.%d.%d", os.time(), math.random(100000, 999999))
            fs.writefile(pwfile, pw .. "\n")
            os.execute("chmod 600 " .. pwfile)
            local rc = helper_call("set-password " .. pwfile)
            fs.unlink(pwfile) -- belt and braces; the helper deletes it too
            msg = (rc == 0) and "pw_ok" or "pw_fail"
        end
    end

    -- Redirect via a meta-refresh page instead of http.redirect(): on the
    -- ucode-era LuCI (24.10's luci-lua-runtime bridge) http.redirect()
    -- produces NO output for bridged Lua controllers — uhttpd answers
    -- "Bad Gateway: the process did not produce any response" while the
    -- operation itself succeeds (field-found on iStoreOS 24.10.8). The
    -- status/write pair provably works (the 403 branch above).
    local target = dispatcher.build_url("admin", "services", "mibee", "settings") .. "?msg=" .. msg
    http.status(200, "OK")
    http.prepare_content("text/html")
    http.write('<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0; url=' .. target .. '">'
        .. '</head><body>OK — <a href="' .. target .. '">continue</a></body></html>')
end
