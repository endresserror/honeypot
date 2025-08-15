
// Enhanced Command Injection Detection Rule
// Generated from comprehensive honeypot analysis

function scanNode(as, msg) {
    // Comprehensive command injection payloads
    var cmdPayloads = [
        // Basic separators
        "; cat /etc/passwd",
        "| ls -la", 
        "&& whoami",
        "|| id",
        
        // Command substitution
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "`whoami`",
        "$(id)",
        
        // System information gathering
        "; uname -a",
        "| cat /proc/version", 
        "&& cat /etc/os-release",
        
        // Network commands
        "; ping -c 3 127.0.0.1",
        "| netstat -an",
        "&& ifconfig",
        
        // File operations
        "; find / -name passwd",
        "| cat /var/log/auth.log",
        "&& ls /home/",
        
        // Windows commands
        "& dir C:\\",
        "&& type C:\\windows\\win.ini",
        "| net user",
        "&& ipconfig /all",
        
        // Encoded payloads
        "%3Bcat%20/etc/passwd",
        "%7Cwhoami",
        "%26%26id"
    ];
    
    // Comprehensive evidence patterns
    var unixEvidence = [
        "root:", "bin/bash", "/etc/passwd", "uid=", "gid=",
        "total ", "drwx", "-rw-", "lrwx", "/home/", "/var/",
        "linux", "ubuntu", "debian", "centos", "kernel"
    ];
    
    var windowsEvidence = [
        "directory of", "volume serial", "<dir>", "c:\\windows",
        "system32", "program files", "documents and settings"
    ];
    
    var systemEvidence = [
        "processor", "architecture", "hostname", "domain",
        "network adapter", "ip address", "subnet mask"
    ];
    
    var errorEvidence = [
        "command not found", "permission denied", "no such file",
        "access denied", "syntax error", "invalid command",
        "is not recognized", "bad command", "cannot execute"
    ];
    
    for (var i = 0; i < cmdPayloads.length; i++) {
        var payload = cmdPayloads[i];
        var testMsg = msg.cloneRequest();
        
        var params = testMsg.getUrlParams();
        for (var j = 0; j < params.size(); j++) {
            var param = params.get(j);
            var newMsg = testMsg.cloneRequest();
            newMsg.setGetParams(param.getName(), payload);
            
            as.sendAndReceive(newMsg, false, false);
            
            var response = newMsg.getResponseBody().toString().toLowerCase();
            var foundEvidence = [];
            var evidenceType = "";
            var risk = 2; // Medium by default
            var confidence = 1; // Low by default
            
            // Check for Unix/Linux evidence
            for (var k = 0; k < unixEvidence.length; k++) {
                if (response.indexOf(unixEvidence[k]) > -1) {
                    foundEvidence.push(unixEvidence[k]);
                    evidenceType = "Unix/Linux command execution";
                    risk = 3; // High
                    confidence = 3; // High
                    break;
                }
            }
            
            // Check for Windows evidence
            if (foundEvidence.length === 0) {
                for (var k = 0; k < windowsEvidence.length; k++) {
                    if (response.indexOf(windowsEvidence[k]) > -1) {
                        foundEvidence.push(windowsEvidence[k]);
                        evidenceType = "Windows command execution";
                        risk = 3; // High
                        confidence = 3; // High
                        break;
                    }
                }
            }
            
            // Check for system information
            if (foundEvidence.length === 0) {
                for (var k = 0; k < systemEvidence.length; k++) {
                    if (response.indexOf(systemEvidence[k]) > -1) {
                        foundEvidence.push(systemEvidence[k]);
                        evidenceType = "System information disclosure";
                        risk = 2; // Medium
                        confidence = 3; // High
                        break;
                    }
                }
            }
            
            // Check for command errors (also indicates injection)
            if (foundEvidence.length === 0) {
                for (var k = 0; k < errorEvidence.length; k++) {
                    if (response.indexOf(errorEvidence[k]) > -1) {
                        foundEvidence.push(errorEvidence[k]);
                        evidenceType = "Command error (injection attempt)";
                        risk = 2; // Medium
                        confidence = 2; // Medium
                        break;
                    }
                }
            }
            
            // Check for time-based injection (response delay)
            var responseTime = newMsg.getTimeElapsedMillis();
            if (responseTime > 5000 && (payload.indexOf("sleep") > -1 || payload.indexOf("ping") > -1)) {
                foundEvidence.push("Response delay: " + responseTime + "ms");
                evidenceType = "Time-based command injection";
                risk = 3; // High
                confidence = 2; // Medium
            }
            
            // Raise alert if evidence found
            if (foundEvidence.length > 0) {
                var description = evidenceType + " detected. Evidence: " + foundEvidence.join(", ");
                
                as.raiseAlert(
                    risk,
                    confidence,
                    "OS Command Injection Vulnerability (" + evidenceType + ")",
                    "Parameter: " + param.getName() + ", Payload: " + payload,
                    newMsg.getRequestHeader().getURI().toString(),
                    param.getName(),
                    payload,
                    description,
                    "Use input validation, parameterized commands, and avoid executing user input",
                    response.substring(0, 300),
                    78,  // CWE-78: OS Command Injection
                    31,  // WASC-31: OS Commanding
                    newMsg
                );
            } else if (payload.indexOf("&") > -1 || payload.indexOf("|") > -1 || payload.indexOf(";") > -1) {
                // Potential injection even without clear evidence
                as.raiseAlert(
                    1, // Low risk
                    1, // Low confidence
                    "Potential OS Command Injection",
                    "Parameter: " + param.getName() + ", Payload: " + payload,
                    newMsg.getRequestHeader().getURI().toString(),
                    param.getName(),
                    payload,
                    "Command injection pattern detected but no execution evidence found",
                    "Use input validation and avoid executing user input",
                    "",
                    78,  // CWE-78
                    31,  // WASC-31
                    newMsg
                );
            }
        }
        
        // Test POST parameters
        if (testMsg.getRequestBody().length() > 0) {
            var newMsg = testMsg.cloneRequest();
            var body = newMsg.getRequestBody().toString();
            if (body.indexOf("=") > -1) {
                var modifiedBody = body + "&cmd_test=" + encodeURIComponent(payload);
                newMsg.setRequestBody(modifiedBody);
                
                as.sendAndReceive(newMsg, false, false);
                
                var response = newMsg.getResponseBody().toString().toLowerCase();
                
                // Same evidence checking logic for POST
                for (var k = 0; k < unixEvidence.length; k++) {
                    if (response.indexOf(unixEvidence[k]) > -1) {
                        as.raiseAlert(
                            3, // High risk
                            3, // High confidence
                            "OS Command Injection Vulnerability (POST)",
                            "POST body injection, Payload: " + payload,
                            newMsg.getRequestHeader().getURI().toString(),
                            "POST body",
                            payload,
                            "Unix/Linux command execution detected: " + unixEvidence[k],
                            "Use input validation and parameterized commands",
                            response.substring(0, 300),
                            78,  // CWE-78
                            31,  // WASC-31
                            newMsg
                        );
                        break;
                    }
                }
            }
        }
    }
}
            