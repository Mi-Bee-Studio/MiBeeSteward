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

function action_apply()
    local http = require "luci.http"
    local dispatcher = require "luci.dispatcher"
    local sys = require "luci.sys"

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
        local rc = sys.call(HELPER .. " restart")
        msg = (rc == 0) and "restart_ok" or "restart_fail"

    elseif act == "enabled" then
        local val = (http.formvalue("enabled") == "1") and "1" or "0"
        local rc = sys.call(string.format("%s set-enabled %s", HELPER, val))
        msg = (rc == 0) and "enabled_ok" or "enabled_fail"

    elseif act == "port" then
        local port = tonumber(http.formvalue("port") or "")
        if port and port == math.floor(port) and port >= 1 and port <= 65535 then
            local rc = sys.call(string.format("%s set-port %d", HELPER, port))
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
            sys.call("chmod 600 " .. pwfile)
            local rc = sys.call(HELPER .. " set-password " .. pwfile)
            fs.unlink(pwfile) -- belt and braces; the helper deletes it too
            msg = (rc == 0) and "pw_ok" or "pw_fail"
        end
    end

    http.redirect(dispatcher.build_url("admin", "services", "mibee", "settings") .. "?msg=" .. msg)
end
