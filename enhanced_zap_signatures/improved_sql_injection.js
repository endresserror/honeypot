
// Improved SQL Injection Detection Rule

function scanNode(as, msg) {
    var sqlPayloads = [
        // Union-based
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,version(),3--",
        "' UNION SELECT 1,user(),database()--",
        
        // Error-based
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, version(), 0x7e))--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM users GROUP BY x)a)--",
        
        // Boolean-based
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        
        // Time-based
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '00:00:05'--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        
        // Second-order
        "admin'; UPDATE users SET password='hacked' WHERE username='admin'--",
        
        // Basic injections
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' OR 'x'='x"
    ];
    
    var sqlErrors = [
        "mysql_fetch_array", "mysql_fetch_assoc", "mysql_num_rows",
        "ora-01756", "ora-00933", "microsoft sql server",
        "odbc sql server driver", "sqlite_step", "sqlite3.operationalerror",
        "postgresql", "psycopg2", "column.*doesn't exist",
        "table.*doesn't exist", "unknown column", "syntax error"
    ];
    
    for (var i = 0; i < sqlPayloads.length; i++) {
        var payload = sqlPayloads[i];
        var testMsg = msg.cloneRequest();
        
        var params = testMsg.getUrlParams();
        for (var j = 0; j < params.size(); j++) {
            var param = params.get(j);
            var newMsg = testMsg.cloneRequest();
            newMsg.setGetParams(param.getName(), payload);
            
            var startTime = new Date().getTime();
            as.sendAndReceive(newMsg, false, false);
            var endTime = new Date().getTime();
            var responseTime = endTime - startTime;
            
            var response = newMsg.getResponseBody().toString().toLowerCase();
            var statusCode = newMsg.getResponseHeader().getStatusCode();
            
            var risk = 1;
            var confidence = 1;
            var evidence = "";
            
            // Check for SQL errors
            for (var k = 0; k < sqlErrors.length; k++) {
                if (response.indexOf(sqlErrors[k]) > -1) {
                    risk = 3;
                    confidence = 3;
                    evidence = "SQL error detected: " + sqlErrors[k];
                    break;
                }
            }
            
            // Check for time-based injection
            if (responseTime > 4000 && (payload.indexOf("SLEEP") > -1 || payload.indexOf("WAITFOR") > -1)) {
                risk = 3;
                confidence = 2;
                evidence = "Time delay detected: " + responseTime + "ms";
            }
            
            // Check for 500 errors (often SQL related)
            if (statusCode == 500 && evidence === "") {
                risk = 2;
                confidence = 2;
                evidence = "HTTP 500 error with SQL injection payload";
            }
            
            if (risk > 1) {
                as.raiseAlert(
                    risk,
                    confidence,
                    "SQL Injection Vulnerability",
                    "Parameter: " + param.getName() + ", Payload: " + payload,
                    newMsg.getRequestHeader().getURI().toString(),
                    param.getName(),
                    payload,
                    evidence,
                    "Use parameterized queries and input validation",
                    response.substring(0, 200),
                    89,  // CWE-89
                    19,  // WASC-19
                    newMsg
                );
            }
        }
    }
}
            