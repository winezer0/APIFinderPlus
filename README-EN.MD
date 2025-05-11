# BurpAPIFinder-Refactor

This plugin is a refactored development based on APIFinder UI [https://github.com/shuanx/BurpAPIFinder] 

### Tips:

Hover over the buttons to see their descriptions; currently, there is no documentation available.

To ensure data integrity, all response body data is saved. If no whitelist is specified, it is recommended to clear the database for each new project to avoid occupying too much space.

### Download Link

Visit https://github.com/winezer0/APIFinderPlus/actions 
```
-> Latest workflow [Green indicates valid] 
-> Summary 
-> Download jar-with-dependencies at the bottom
```

### Plugin Goals

Create the most comprehensive API mining tool,  
Reduce manual path extraction and testing,  
Supplement operations that cannot be handled automatically,  

    1. Support extraction of sensitive information, URLs, and URI information from response data.
    2. Support automatic calculation of actual URLs based on known path information.
    3. Support automatic access to mined URL information for recursive information extraction.
    4. Support simple format extraction and splicing of webpack's JS files (limited format but high accuracy).

Combination format abcd.xxxx.js  
![Simple webpack format. Character type](./doc/webpack简单格式.字符型.png)

Combination format 1234.xxxx.js  
![Simple webpack format. Numeric type](./doc/webpack简单格式.数字型.png)

### Notes

    1. All data is stored and read using SQLite, which is slower than in-memory operations.
    2. When there are too many targets, executing tasks like refreshing unvisited URLs or automatic recursive scanning may consume a significant amount of memory.
    3. Due to the abundance of features, hover over text or buttons to view operation descriptions.

### Basic Workflow [Old Version]

![APIFinder Workflow](./doc/APIFinder运行流程.png)


### Main Tasks [Updated]

```
Scheduled Task Thread:
- Query the ReqDataTable in the database
  - Check if there are any unanalyzed messages
    - Match and extract sensitive information, URLs, and PATHs from requests/responses based on rule configurations
      - Save analysis results to the AnalyseUrlResultTable in the database
- Query the AnalyseUrlResultTable in the database
    - Categorize new results in the AnalyseUrlResultTable by RootUrl and insert them into the AnalyseHostResultTable

- autoPathsToUrlsIsOpen: Enable automatic URL calculation based on paths (disabled by default, supports manual operation)
  - Query the RecordPathTable in the database
    - Check if there are valid request PATHs not yet added to the website path tree
      - Calculate/update the PathTree based on recorded URL paths
        - Save analysis results to the PathTree table
        
  - Query the database by combining PathTreeTable and AnalyseHostResultTable
    - Check if there are updated PathTrees that have not been recalculated for PATH URLs
      - Calculate possible prefixes for new PATHs based on the updated PathTree
        - Save analysis results to the PATH-calculated URL in the AnalyseHostResultTable

- autoRecursiveIsOpen: Enable automatic access to unvisited URLs
  - Query the AnalyseHostResultTable in the database
    - Check if all URLs have been visited
      - Construct HTTP requests for unvisited URLs
```

### Internal Rule Explanation
```
    Note: Rules starting with CONF_ and located in "config" are internal rules and are not used for information matching.

    CONF_DEFAULT_PERFORMANCE: Default performance configuration
        "maxPatterChunkSizeDefault=1000000": Maximum response length for regex matching in one operation. Changes take effect immediately after saving.
        "maxStoreRespBodyLenDefault=1000000": Maximum size of response body saved in the database. Changes take effect immediately after saving.
        "monitorExecutorIntervalsDefault=4": Interval (in seconds) for executing extraction checks. Changes take effect immediately after saving.
        Other default UI button-related parameters take effect after saving and restarting the plugin.
    
    Custom automatic request scanning methods:
        1. CONF_RECURSE_REQ_HTTP_METHODS: Customize supported HTTP request methods (one method per line).
        2. CONF_RECURSE_REQ_HTTP_PARAMS: Configure keywords to prevent automatic scanning of URLs, such as [logout, del], to avoid accidental deletions.
        3. CONF_BLACK_RECURSE_REQ_PATH_KEYS: Support custom request parameters (write one set of request parameters per line; multiple lines will be iterated).
       Note: The request headers for the current request are dynamically obtained from the current URL request body. Custom request header functionality will be added based on user needs.
  
  
    CONF_WHITE_ROOT_URL: Keywords for allowed RootUrls to scan.
    CONF_BLACK_ROOT_URL: Keywords for RootUrls prohibited from [monitoring scans | URL extraction | PATH extraction].
    CONF_BLACK_URI_PATH_KEYS: Keywords for URI paths prohibited from [monitoring scans | URL extraction | PATH extraction].
    CONF_BLACK_URI_EXT_EQUAL: File extensions prohibited from [monitoring scans | URL extraction | PATH extraction].
    CONF_BLACK_AUTO_RECORD_PATH: Keywords for RootUrls prohibited from automatic PATH recording.
    CONF_BLACK_AUTO_RECURSE_SCAN: Keywords for RootUrls prohibited from automatic scanning of unvisited URLs.
    CONF_WHITE_RECORD_PATH_STATUS: Response status codes allowed for automatic PATH recording.
    CONF_BLACK_RECORD_PATH_TITLE: Response titles prohibited from automatic PATH recording.
    CONF_BLACK_EXTRACT_PATH_EQUAL: URI paths prohibited from extraction [equal to any element in this list].
    CONF_BLACK_EXTRACT_INFO_KEYS: Sensitive information prohibited from extraction [containing any element in this list].
    CONF_REGULAR_EXTRACT_URIS: Regular expressions for extracting response URIs/URLs.
```

### Matching Rule Explanation

```

Matching Location ("location" field):  
    locations =    
        CONFIG("config"): Configuration rules, not involved in matching.
        PATH("path"): Request path.
        TITLE("title"): Response title <title>(.*)</title>.
        BODY("body"): Response body.
        HEADER("header"): Response header.
        RESPONSE("response"): Entire response content.
        ICON_HASH("icon_hash"): Hash of the ico file, only obtained when the file is of ico type.


Matching Method ("matchType" field):  
    1. Keyword Matching  
        ANY_KEYWORDS("any_keywords"): Match any keyword rule (common). Supports || and && syntax.
        ALL_KEYWORDS("all_keywords"): Match all keyword rules (rare). Supports || and && syntax.
    2. Regex Matching  
        ANY_REGULAR("any_regular"): Match any regex rule (common).
        ALL_REGULAR("all_regular"): Match all regex rules (rare).

Actual Matching Rules ("matchKeys": [] list):  
     1. Keyword Matching Rule Writing  
        Each line is a keyword extraction matching rule.  
        Each line's content supports multiple keywords joined together using the symbol 【|】.  
        Example:  
            "matchType": "any_keywords" + "matchKeys": ["fzhm1&&total1&&rows1", "fzhm2&&total2&&rows2"],  
             Indicates that it requires fzhm1, total1, and rows1 keywords simultaneously or fzhm2, total2, and rows2 simultaneously.  
             
            "matchType": "all_keywords" + "matchKeys": ["fzhm1||fzhm2","total1||total2"],  
             Indicates that it requires at least one fzhm* and at least one total* keyword simultaneously.  
        Note:  
            1. This rule differs from the original version.  
            2. Since it uses syntax symbols 【|| &&】, matching keywords cannot contain 【|| &&】.  
            
     2. Regex Matching Rule Writing  
        Each line is a regex extraction matching rule.  


                
Other Keywords:  
    "accuracy": Rule accuracy.  
    "describe": Rule description.  
    "isImportant": Whether the matching result is important.  
    "isOpen": Whether the rule is enabled.  
    "type": Rule category.  
    
```
