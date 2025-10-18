-- Step-up authentication handler for Envoy
-- This script intercepts step-up responses and manages the MFA redirect flow

function envoy_on_request(request_handle)
    -- Check if this is an MFA verification callback
    local path = request_handle:headers():get(":path")
    if path and string.match(path, "^/auth/mfa/callback") then
        return handle_mfa_callback(request_handle)
    end
end

function envoy_on_response(response_handle)
    local status = response_handle:headers():get(":status")
    local content_type = response_handle:headers():get("content-type")
    
    -- Intercept 403 responses with JSON content (step-up required)
    if status == "403" and content_type and string.match(content_type, "application/json") then
        return handle_stepup_response(response_handle)
    end
end

function handle_stepup_response(response_handle)
    -- Read the response body
    local body = response_handle:body()
    if not body then
        return
    end
    
    -- Try to parse JSON response
    local json_response = parse_json(body:getBytes(0, body:length()))
    if not json_response or json_response.error ~= "mfa_required" then
        return -- Not a step-up response, continue normally
    end
    
    -- Extract MFA session information
    local session_id = json_response.session_id or ""
    local device_id = json_response.device_id or ""
    local mfa_url = json_response.mfa_url or "http://mfa:8445/mfa/challenge"
    
    -- Create MFA challenge request
    local challenge_data = {
        session_id = session_id,
        device_id = device_id,
        user_email = extract_user_email_from_request()
    }
    
    -- Initiate MFA challenge
    local mfa_response = call_mfa_service(mfa_url, challenge_data)
    if not mfa_response then
        response_handle:logErr("Failed to create MFA challenge")
        return
    end
    
    -- Create redirect response to MFA interface
    local redirect_url = string.format("/auth/mfa?session=%s&challenge=%s&code=%s", 
                                       session_id, 
                                       url_encode(mfa_response.challenge or ""),
                                       mfa_response.code or "") -- Only for PoC
    
    response_handle:headers():remove("content-length")
    response_handle:headers():add("location", redirect_url)
    response_handle:headers():add("content-type", "text/html")
    response_handle:headers():replace(":status", "302")
    
    -- Create redirect page with MFA form
    local redirect_html = create_mfa_form(session_id, mfa_response.challenge, mfa_response.code)
    response_handle:body():setBytes(redirect_html)
end

function handle_mfa_callback(request_handle)
    local query_params = parse_query_string(request_handle:headers():get(":path"))
    local session_id = query_params.session or ""
    local code = query_params.code or ""
    
    if session_id == "" or code == "" then
        send_error_response(request_handle, "Invalid MFA parameters")
        return
    end
    
    -- Verify MFA code
    local verify_data = {
        session_id = session_id,
        code = code
    }
    
    local verify_response = call_mfa_verify("http://mfa:8445/mfa/verify", verify_data)
    if not verify_response or verify_response.status ~= "verified" then
        send_error_response(request_handle, "MFA verification failed")
        return
    end
    
    -- MFA successful - redirect back to original request with MFA token
    local original_path = query_params.original_path or "/"
    local mfa_token = verify_response.token or ""
    
    request_handle:headers():add("x-mfa-token", mfa_token)
    request_handle:headers():add("x-mfa-verified", "true")
    request_handle:headers():replace(":path", original_path)
    
    -- Continue with original request
end

function call_mfa_service(url, data)
    local headers, body = request_handle:httpCall(
        "mfa_cluster",
        {
            [":method"] = "POST",
            [":path"] = "/mfa/challenge",
            [":authority"] = "mfa:8445",
            ["content-type"] = "application/json"
        },
        json_encode(data),
        5000
    )
    
    if not body then
        return nil
    end
    
    return parse_json(body)
end

function call_mfa_verify(url, data)
    local headers, body = request_handle:httpCall(
        "mfa_cluster", 
        {
            [":method"] = "POST",
            [":path"] = "/mfa/verify",
            [":authority"] = "mfa:8445",
            ["content-type"] = "application/json"
        },
        json_encode(data),
        5000
    )
    
    if not body then
        return nil
    end
    
    return parse_json(body)
end

function create_mfa_form(session_id, challenge, code)
    return string.format([[
<!DOCTYPE html>
<html>
<head>
    <title>Additional Authentication Required</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        .form-group { margin: 15px 0; }
        input[type="text"] { width: 100%%; padding: 10px; font-size: 18px; text-align: center; }
        button { width: 100%%; padding: 15px; background: #007cba; color: white; border: none; font-size: 16px; }
        .challenge { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .code { font-weight: bold; color: #007cba; font-size: 24px; text-align: center; margin: 20px 0; }
    </style>
</head>
<body>
    <h2>Additional Authentication Required</h2>
    <div class="challenge">%s</div>
    <div class="code">Code: %s</div>
    <form id="mfaForm" method="GET" action="/auth/mfa/callback">
        <input type="hidden" name="session" value="%s">
        <input type="hidden" name="original_path" value="%s">
        <div class="form-group">
            <input type="text" name="code" placeholder="Enter 6-digit code" maxlength="6" required>
        </div>
        <button type="submit">Verify</button>
    </form>
</body>
</html>]], challenge, code, session_id, get_original_path())
end

-- Utility functions
function parse_json(str)
    -- Basic JSON parsing (would use proper library in production)
    local json = {}
    for key, value in string.gmatch(str, '"([^"]+)"%s*:%s*"([^"]*)"') do
        json[key] = value
    end
    for key, value in string.gmatch(str, '"([^"]+)"%s*:%s*([%d%.]+)') do
        json[key] = tonumber(value)
    end
    return json
end

function json_encode(data)
    local result = "{"
    local first = true
    for key, value in pairs(data) do
        if not first then
            result = result .. ","
        end
        if type(value) == "string" then
            result = result .. string.format('"%s":"%s"', key, value)
        else
            result = result .. string.format('"%s":%s', key, tostring(value))
        end
        first = false
    end
    result = result .. "}"
    return result
end

function parse_query_string(path)
    local params = {}
    if path then
        local query = string.match(path, "^[^%?]*%?(.*)$")
        if query then
            for key, value in string.gmatch(query, "([^&=]+)=([^&]*)") do
                params[key] = url_decode(value)
            end
        end
    end
    return params
end

function url_encode(str)
    if str then
        str = string.gsub(str, "([^%w%-%.%_%~ ])", function(c)
            return string.format("%%%02X", string.byte(c))
        end)
        str = string.gsub(str, " ", "+")
    end
    return str
end

function url_decode(str)
    if str then
        str = string.gsub(str, "+", " ")
        str = string.gsub(str, "%%(%x%x)", function(h)
            return string.char(tonumber(h, 16))
        end)
    end
    return str
end

function extract_user_email_from_request()
    -- Extract from JWT or other source
    return "user@example.com" -- Placeholder
end

function get_original_path()
    -- Get the original request path
    return "/" -- Placeholder
end

function send_error_response(request_handle, message)
    request_handle:respond(
        {[":status"] = "400", ["content-type"] = "text/html"},
        string.format("<html><body><h1>Error</h1><p>%s</p></body></html>", message)
    )
end
