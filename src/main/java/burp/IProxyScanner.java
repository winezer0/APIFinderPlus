package burp;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import database.*;
import model.*;
import ui.ConfigPanel;
import utilbox.HelperPlus;
import utils.*;

import java.util.*;
import java.util.concurrent.*;

import static burp.BurpExtender.*;
import static utils.BurpPrintUtils.*;
import static utils.CastUtils.*;
import static utils.ElementUtils.isContainOneKey;
import static utils.ElementUtils.isEqualsOneKey;


public class IProxyScanner implements IProxyListener {
    public static int totalRequestCount = 0;  //记录所有经过插件的请求数量
    public static final int MaxRespBodyLen = 500000; //最大支持存储的响应 比特长度

    public static RecordHashMap urlScanRecordMap = new RecordHashMap(); //记录已加入扫描列表的URL 防止重复扫描

    public static ThreadPoolExecutor executorService = null;
    public static ScheduledExecutorService monitorExecutor;
    private static int monitorExecutorServiceNumberOfIntervals = 2;

    //存储每个host的对比对象
    public static Map<String, Map<String,Object>> urlCompareMap = new HashMap<>(); //存储每个域名的对比关系,后续可以考虑写入到数据库
    private static ConcurrentHashMap<String, Map<String,Object>> notCompareMap = new ConcurrentHashMap<>();  //在域名对比关系生成前,需要把响应信息先存起来,等后续再进行处理

    public static boolean dynamicPthFilterIsOpen = true;    //是否启用增强的path过滤模式

    public static boolean autoRecordPathIsOpen  = true;     //是否启用自动记录每个录得PATH
    public static boolean autoPathsToUrlsIsOpen = false;    //是否进行自动PathTree生成URL
    public static boolean autoRecursiveIsOpen = false;      //是否进行递归URL扫描

    //持久化保存对象的Hash
    private String urlCompareMapCacheFile = String.format("%s.urlCompareMap.json", configName);
    private String urlCompareMapHistoryHash = null;
    private int urlCompareMapHistorySize = 0;

    //设置最大进程数量
    private int maxPoolSize = 10;

    //开关插件的监听功能
    public static boolean proxyListenIsOpen = true;

    public IProxyScanner() {
        //加载缓存过滤器
        urlCompareMap = BurpFileUtils.LoadJsonFromFile(urlCompareMapCacheFile);
        // 获取操作系统内核数量
        int availableProcessors = Runtime.getRuntime().availableProcessors();
        int coreCount = Math.min(availableProcessors, 16);
        maxPoolSize = coreCount * 2;

        // 高性能模式  //控制ScheduledExecutorService中任务的执行频率或周期。
        monitorExecutorServiceNumberOfIntervals = (availableProcessors > 6) ? 1 : monitorExecutorServiceNumberOfIntervals;
        long keepAliveTime = 60L;

        // 创建一个足够大的队列来处理您的任务
        BlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>(10000);

        executorService = new ThreadPoolExecutor(
                coreCount,  //CorePoolSize 线程池中始终保持运行的线程数
                maxPoolSize, //线程池中的活动线程达到coreCount并且还有任务等待执行时 线程池可以扩展到的最大线程数
                keepAliveTime, //如果线程池中的线程数超过coreCount，那么超出的线程将在60秒内被终止，除非它们在这段时间内获得新任务。
                TimeUnit.SECONDS,
                workQueue, //BlockingQueue，用于保存等待执行的任务。当线程池中的线程数达到maxPoolSize时，新的任务会被放入队列中等待执行。
                Executors.defaultThreadFactory(), //创建新线程。默认的工厂会创建具有默认优先级的守护线程。
                new ThreadPoolExecutor.AbortPolicy()
                // 当workQueue满了且线程数达到maxPoolSize时，线程池会使用AbortPolicy来处理额外的任务 即抛出RejectedExecutionException。
                // 可以根据需要替换为其他的策略，如CallerRunsPolicy（调用者运行），DiscardPolicy（丢弃任务），或DiscardOldestPolicy（丢弃队列中最老的任务）。
        );
        stdout_println(LOG_INFO,"[+] run executorService maxPoolSize: " + coreCount + " ~ " + maxPoolSize + ", monitorExecutorServiceNumberOfIntervals: " + monitorExecutorServiceNumberOfIntervals);

        //使用单一的后台线程来执行所有周期性或定时任务。这通常用于那些不需要并行处理的定时任务，例如监控、定期日志记录等。
        monitorExecutor = Executors.newSingleThreadScheduledExecutor();

        startDatabaseMonitor();
    }

    /**
     * 添加右键扫描任务
     */
    public static void addRightScanTask(IHttpRequestResponse iInterceptedProxyMessage) {
        if (true){
            //记录并更新UI面板中的扫描计数
            totalRequestCount += 1;
            ConfigPanel.lbRequestCount.setText(String.valueOf(totalRequestCount));

            //解析当前请求的信息
            HttpMsgInfo msgInfo = new HttpMsgInfo(iInterceptedProxyMessage);
            String statusCode = String.valueOf(msgInfo.getRespStatusCode());
            String rawUrlUsual = msgInfo.getUrlInfo().getRawUrlUsual();

            //看URL识别是否报错 不记录报错情况
            if (msgInfo.getUrlInfo().getUrlToFileUsual() == null){
                stdout_println(LOG_ERROR,"[-] URL转化失败 跳过url识别：" + rawUrlUsual);
                return;
            }

            if (msgInfo.getRespBytes() == null || msgInfo.getRespBytes().length == 0) {
                stdout_println(LOG_DEBUG,"[-] 没有响应内容 跳过插件处理：" + rawUrlUsual);
                return;
            }

            //判断是否是正常的响应 不记录无响应情况
            if(autoRecordPathIsOpen
                    && isEqualsOneKey(statusCode, CONF_ALLOW_RECORD_STATUS, false)
                    && !msgInfo.getUrlInfo().getPathToDir().equals("/")
                    && !isContainOneKey(msgInfo.getUrlInfo().getUrlToFileUsual(), CONF_NOT_AUTO_RECORD, false)
                    && !isContainOneKey(msgInfo.getRespInfo().getRespTitle(), CONF_NOT_RECORD_TITLE, false)
            ){
                executorService.submit(new Runnable() {
                    @Override
                    public void run() {
                        enhanceRecordPathFilter(msgInfo, dynamicPthFilterIsOpen);
                    }
                });
            }

            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    //更新所有有响应的主动访问请求URL记录到数据库中  //记录请求记录到数据库中（记录所有请求）
                    RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);
                }
            });

            //判断URL是否已经扫描过
            if (urlScanRecordMap.get(rawUrlUsual) <= 0) {
                //应该放到后面,确保已经记录数据,不然会被过滤掉
                urlScanRecordMap.add(rawUrlUsual);
                executorService.submit(new Runnable() {
                    @Override
                    public void run() {
                        //加入请求列表
                        insertOrUpdateReqDataAndReqMsgData(msgInfo,"Right");
                    }
                });
            }
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, final IInterceptedProxyMessage iInterceptedProxyMessage) {
        if(!proxyListenIsOpen){
            return;
        }

        if (!messageIsRequest) {
            //记录并更新UI面板中的扫描计数
            totalRequestCount += 1;
            ConfigPanel.lbRequestCount.setText(String.valueOf(totalRequestCount));

            //解析当前请求的信息
            HttpMsgInfo msgInfo = new HttpMsgInfo(iInterceptedProxyMessage);
            String statusCode = String.valueOf(msgInfo.getRespStatusCode());
            String reqRootUrl = msgInfo.getUrlInfo().getRootUrlUsual();
            String rawUrlUsual = msgInfo.getUrlInfo().getRawUrlUsual();

            //看URL识别是否报错 不记录报错情况
            if (msgInfo.getUrlInfo().getUrlToFileUsual() == null){
                stdout_println(LOG_ERROR,"[-] URL转化失败 跳过url识别：" + rawUrlUsual);
                return;
            }

            //如果白名单开启,对于其他URL直接忽略
            if (!isContainOneKey(reqRootUrl, CONF_WHITE_URL_ROOT, true)){
                //stdout_println(LOG_DEBUG,"[-] 不匹配白名单域名 跳过url识别：" + rawUrlUsual);
                return;
            }

            //匹配黑名单域名 黑名单域名相关的文件和路径都是无用的
            if(isContainOneKey(reqRootUrl, CONF_BLACK_URL_ROOT, false)){
                //stdout_println(LOG_DEBUG,"[-] 匹配黑名单域名 跳过url识别：" + rawUrlUsual);
                return;
            }

            if (msgInfo.getRespBytes() == null || msgInfo.getRespBytes().length == 0) {
                stdout_println(LOG_DEBUG,"[-] 没有响应内容 跳过插件处理：" + rawUrlUsual);
                return;
            }

            //判断是否是正常的响应 不记录无响应情况
            if(autoRecordPathIsOpen
                    && isEqualsOneKey(statusCode, CONF_ALLOW_RECORD_STATUS, false)
                    && !msgInfo.getUrlInfo().getPathToDir().equals("/")
                    && !isContainOneKey(msgInfo.getUrlInfo().getUrlToFileUsual(), CONF_NOT_AUTO_RECORD, false)
                    && !isContainOneKey(msgInfo.getRespInfo().getRespTitle(), CONF_NOT_RECORD_TITLE, false)
            ){
                executorService.submit(new Runnable() {
                    @Override
                    public void run() {
                        enhanceRecordPathFilter(msgInfo, dynamicPthFilterIsOpen);
                    }
                });
            }

            // 排除黑名单后缀 ||  排除黑名单路径 "jquery.js|xxx.js" 这些JS文件是通用的、无价值的、
            if(isEqualsOneKey(msgInfo.getUrlInfo().getSuffix(), CONF_BLACK_URL_EXT, false)
                    || isContainOneKey(msgInfo.getUrlInfo().getPathToFile(), CONF_BLACK_URL_PATH, false))
            {
                //stdout_println(LOG_DEBUG, "[-] 匹配黑名单后缀|路径 跳过url识别：" + rawUrlUsual);
                return;
            }

            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    //更新所有有响应的主动访问请求URL记录到数据库中  //记录请求记录到数据库中（记录所有请求）
                    RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);
                }
            });

            // 看status是否为30开头 || 看status是否为4  403 404 30x 都是没有敏感数据和URl的,可以直接忽略
            if (statusCode.startsWith("3") || statusCode.startsWith("4")){
                //stdout_println(LOG_DEBUG, "[-] 匹配30X|404 页面 跳过url识别：" + rawUrlUsual);
                return;
            }

            //判断URL是否已经扫描过
            if (urlScanRecordMap.get(rawUrlUsual) <= 0) {
                //应该放到后面,确保已经记录数据,不然会被过滤掉
                urlScanRecordMap.add(rawUrlUsual);
                executorService.submit(new Runnable() {
                    @Override
                    public void run() {
                        //加入请求列表
                        insertOrUpdateReqDataAndReqMsgData(msgInfo,"Proxy");
                    }
                });
            }
        } else {
            //解析当前请求的信息
            HttpMsgInfo msgInfo = new HttpMsgInfo(iInterceptedProxyMessage);
            String reqRootUrl = msgInfo.getUrlInfo().getRootUrlUsual();

            //看URL识别是否报错 //如果白名单开启, //匹配黑名单域名  // 排除黑名单后缀  //排除黑名单路径文件
            if (msgInfo.getUrlInfo().getUrlToFileUsual() == null
                    ||!isContainOneKey(reqRootUrl, CONF_WHITE_URL_ROOT, true)
                    ||isContainOneKey(reqRootUrl, CONF_BLACK_URL_ROOT, false)
                    ||isEqualsOneKey(msgInfo.getUrlInfo().getSuffix(), CONF_BLACK_URL_EXT, false)
                    ||isContainOneKey(msgInfo.getUrlInfo().getPathToFile(), CONF_BLACK_URL_PATH, false)
            ){
                return;
            }

            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    //记录请求记录到数据库中（记录所有请求）
                    RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);
                }
            });
        }
    }

    /**
     * 增强的有效路径判断过滤函数
     */
    public static void enhanceRecordPathFilter(HttpMsgInfo msgInfo, boolean dynamicPthFilterIsOpen) {
        if (!dynamicPthFilterIsOpen){
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    //保存网站相关的所有 PATH, 便于后续path反查的使用 当响应状态 In [200 | 403 | 405] 说明路径存在 方法不准确, 暂时关闭
                    RecordPathTable.insertOrUpdateRecordPath(msgInfo);
                    stdout_println(LOG_DEBUG, String.format("Common Direct Record reqBaseUrl: %s", msgInfo.getUrlInfo().getUrlToPathUsual()));
                }
            });
        } else {
            String reqRootUrl = msgInfo.getUrlInfo().getRootUrlUsual();
            String reqUrlToFile = msgInfo.getUrlInfo().getUrlToFileUsual();

            //首先转换为响应Map
            Map<String, Object> respFieldsMap = new RespFieldsModel(msgInfo.getRespInfo()).getAllFieldsAsMap();
            if (!urlCompareMap.containsKey(reqRootUrl)){
                //存储未进行对比的目标,后续通过定时任务再进行对比
                notCompareMap.put(reqUrlToFile, respFieldsMap);
                //记录状态为正在生成,避免重复调用 GenerateDynamicFilterMap
                if (!msgInfo.getUrlInfo().getPathToDir().equals("/")){
                    urlCompareMap.put(reqRootUrl, null);
                    executorService.submit(new Runnable() {
                        @Override
                        public void run() {
                            //计算动态过滤条件
                            Map<String, Object> filterModel = RespFieldCompareutils.generateDynamicFilterMap(msgInfo);
                            urlCompareMap.put(reqRootUrl, filterModel);
                        }
                    });
                }
            } else {
                Map<String, Object> currentFilterMap = urlCompareMap.get(reqRootUrl);
                if (currentFilterMap == null){
                    //存储未进行对比的目标,后续通过定时任务再进行对比
                    notCompareMap.put(reqUrlToFile, respFieldsMap);
                } else {
                    //当存在对比规则的时候,就进行对比,没有规则，说明目录猜不出来,只能人工添加
                    if(isNotEmptyObj(currentFilterMap) && !RespFieldCompareutils.sameFieldValueIsEquals(respFieldsMap, currentFilterMap, false)){
                        executorService.submit(new Runnable() {
                            @Override
                            public void run() {
                                //插入数据库记录
                                RecordPathTable.insertOrUpdateRecordPath(msgInfo);
                                stdout_println(LOG_DEBUG, String.format("[+] Dynamic Compare Record reqBaseUrl: %s", msgInfo.getUrlInfo().getUrlToPathUsual()));
                            }
                        });
                   }
                }
            }
        }
    }

    /**
     * 合并添加请求数据和请求信息为一个函数
     * @param msgInfo
     * @param reqSource
     */
    static void insertOrUpdateReqDataAndReqMsgData(HttpMsgInfo msgInfo, String reqSource) {
        //防止响应体过大
        if (msgInfo.getRespBytes().length > MaxRespBodyLen){
            byte[] respBytes = Arrays.copyOf(msgInfo.getRespBytes(), MaxRespBodyLen);
            msgInfo.setRespBytes(respBytes);
        }

        //存储请求体|响应体数据
        int msgDataIndex = ReqMsgDataTable.insertOrUpdateMsgData(msgInfo);
        if (msgDataIndex > 0){
            // 存储到URL表
            int insertOrUpdateOriginalDataIndex = ReqDataTable.insertOrUpdateReqData(msgInfo, msgDataIndex, reqSource);
            if (insertOrUpdateOriginalDataIndex > 0)
                stdout_println(LOG_INFO, String.format("[+] Success Add Task: %s -> msgHash: %s -> reqSource:%s",
                        msgInfo.getUrlInfo().getUrlToFileUsual(), msgInfo.getMsgHash(), reqSource));
        }
    }

    /**
     * 启动动态监听的数据处理
     */
    private void startDatabaseMonitor() {
        monitorExecutor.scheduleAtFixedRate(() -> {
            executorService.submit(() -> {
                try {
                    //当添加进程还比较多的时候,暂时不进行响应数据处理
                    if (executorService.getActiveCount() >= 6)
                        return;

                    //定时清理URL记录表
                    if (UnionTableSql.getTableCounts(RecordUrlTable.tableName) > 500){
                        stdout_println(LOG_INFO, "[*] cleaning the RecordUrlTable");
                        DBService.clearRecordUrlTable();
                    }

                    //存储一下当前的过滤器
                    if (urlCompareMap.size() != urlCompareMapHistorySize){
                        urlCompareMapHistorySize = urlCompareMap.size();
                        String urlCompareMapJson = CastUtils.toJsonString(urlCompareMap);
                        String currentJsonHash = calcCRC32(urlCompareMapJson);
                        if(!currentJsonHash.equals(urlCompareMapHistoryHash)){
                            urlCompareMapHistoryHash = currentJsonHash;
                            BurpFileUtils.writeToPluginPathFileNotEx(urlCompareMapCacheFile, urlCompareMapJson);
                            stdout_println(LOG_DEBUG, String.format("[*] Save urlCompareMap To Cache Json: %s", urlCompareMapCacheFile));
                        }
                    }

                    //清理在等待动态过滤Map生成过程中没有处理的响应对象
                    if (dynamicPthFilterIsOpen && isNotEmptyObj(notCompareMap)){
                        // 创建一个ArrayList来保存所有的键，这是一个安全的迭代方式
                        ArrayList<String> keys = new ArrayList<>(notCompareMap.keySet());
                        // 遍历键的列表
                        for (String reqUrl : keys) {
                            Map<String,Object> respFieldsMap = notCompareMap.get(reqUrl);
                            String rootUrl = new HttpUrlInfo(reqUrl).getRootUrlUsual();
                            Map<String, Object> currentFilterMap = urlCompareMap.get(rootUrl);

                            if (currentFilterMap != null){
                                if(isNotEmptyObj(currentFilterMap)
                                        && !RespFieldCompareutils.sameFieldValueIsEquals(respFieldsMap, currentFilterMap, false)){
                                    int setStatusCode = respFieldsMap.get("StatusCode") == null ? 299: (int) respFieldsMap.get("StatusCode");
                                    RecordPathTable.insertOrUpdateRecordPath(reqUrl, setStatusCode);
                                    stdout_println(LOG_DEBUG, String.format("[+] Insert Temp Record reqBaseUrl: %s", reqUrl));
                                }
                                notCompareMap.remove(reqUrl);
                            }
                        }
                        // 先返回进行其他操作
                        return;
                    }


                    //任务1、获取需要解析的响应体数据并进行解析响
                    List<Integer> msgDataIndexList = ReqDataTable.fetchUnhandleReqDataMsgDataIndexList(maxPoolSize);
                    if (msgDataIndexList.size() > 0){
                        //更新对应的ids为已经检查 防止其他进程获取这些数据
                        int updateCount = ReqDataTable.updateReqDataStatusByMsgDataIndex(msgDataIndexList);
                        if(updateCount>0){
                            //循环进行数据获取和分析操作
                            for (int msgDataIndex : msgDataIndexList){
                                //逐个 获取 msgDataIndex 对应的数据 . 一次性获取数据太多了
                                ReqMsgDataModel msgData = ReqMsgDataTable.fetchMsgDataById(msgDataIndex);
                                if (msgData != null){
                                    HttpMsgInfo msgInfo =  new HttpMsgInfo(
                                            msgData.getReqUrl(),
                                            msgData.getReqBytes(),
                                            msgData.getRespBytes(),
                                            msgData.getMsgHash()
                                    );
                                    if (!msgData.getMsgHash().equals(msgInfo.getMsgHash())){
                                        stderr_println(LOG_ERROR, String.format("[!] 发生严重错误 URL的新旧Hash不一致: %s -> %s", msgData.getMsgHash(), msgInfo.getMsgHash()));
                                    }

                                    //进行数据分析
                                    AnalyseResultModel analyseResult = AnalyseInfo.analyseMsgInfo(msgInfo);
                                    //存入分析结果
                                    if(isNotEmptyObj(analyseResult.getInfoList()) || isNotEmptyObj(analyseResult.getPathList())  || isNotEmptyObj(analyseResult.getUrlList())){
                                        //将初次分析结果写入数据库
                                        int analyseDataIndex = AnalyseResultTable.insertBasicAnalyseResult(msgInfo, analyseResult);
                                        if (analyseDataIndex > 0){
                                            stdout_println(LOG_INFO, String.format("[+] Analysis Result Write Success: %s -> %s", msgInfo.getUrlInfo().getRawUrlUsual(), msgInfo.getMsgHash()));
                                        }
                                    }
                                }
                            }
                        }
                        return;
                    }


                    if (autoPathsToUrlsIsOpen){
                        //任务2、如果没有需要分析的数据,就更新Path树信息 为动态 path to url 做准备
                        //获取需要更新的所有URL记录
                        List<RecordPathDirsModel> recordPathDirsModels = RecordPathTable.fetchAllNotAddToTreeRecords();
                        if (recordPathDirsModels.size()>0){
                            for (RecordPathDirsModel recordPathModel : recordPathDirsModels) {
                                //生成新的路径树
                                PathTreeModel pathTreeModel = PathTreeUtils.genPathsTree(recordPathModel);
                                if (pathTreeModel != null){
                                    //合并|插入新的路径树
                                    int pathTreeIndex = PathTreeTable.insertOrUpdatePathTree(pathTreeModel);
                                    if (pathTreeIndex > 0)
                                        stdout_println(LOG_DEBUG, String.format("[+] Path Tree Update Success: %s",pathTreeModel.getReqHostPort()));
                                }
                            }
                            //更新数据后先返回,优先进行之前的操作
                            return;
                        }

                        //任务3、判断是否存在未处理的Path路径,没有的话就根据树生成计算新的URL
                        //获取多条需要分析【状态为待解析】的数据
                        List<Integer> findPathIds = AnalyseResultTable.fetchUnhandledPathDataIds(maxPoolSize);
                        if (findPathIds.size()>0){
                            //更新ids对应的状态,防止其他线程读取
                            int updateCount = AnalyseResultTable.updatePathDataStatusByIds(findPathIds);
                            if (updateCount>0){
                                //一次性 获取实际的数据进行修改
                                List<FindPathModel> findPathModelList = AnalyseResultTable.fetchPathDataByIds(findPathIds);
                                for (FindPathModel findPathModel:findPathModelList){
                                    stdout_println(LOG_DEBUG, String.format("[*] 获取未处理PATH数据进行URL计算 PathNum: %s", findPathModel.getFindPath().size()));
                                    pathsToUrlsByPathTree(findPathModel);
                                }
                            }
                            return;
                        }

                        //任务4、如果没有获取成功, 就获取 基准路径树 小于 PathTree基准的数据进行更新
                        List<FindPathModel> findPathModelList = UnionTableSql.fetchNeedUpdatePathDataList(maxPoolSize);
                        if (findPathModelList.size()>0){
                            for (FindPathModel findPathModel:findPathModelList) {
                                stdout_println(LOG_DEBUG, String.format("[*] 获取动态更新PATHTree进行重计算 PathNum: %s", findPathModel.getFindPath().size()));
                                pathsToUrlsByPathTree(findPathModel);
                            }
                            return;
                        }
                    }

                    // 自动递归查询功能
                    if (autoRecursiveIsOpen && executorService.getActiveCount() < 2){
                        //获取一个未访问URL列表
                        executorService.submit(new Runnable() {
                            @Override
                            public void run() {
                                //将URL访问过程作为一个基本任务外放, 可能会频率过快, 目前没有问题
                                UnVisitedUrlsModel unVisitedUrlsModel =  AnalyseResultTable.fetchOneUnVisitedUrls( );
                                accessUnVisitedUrlsModel(unVisitedUrlsModel, true);
                            }
                        });
                        return;
                    }

                } catch (Exception e) {
                    stderr_println(String.format("[!] scheduleAtFixedRate error: %s", e.getMessage()));
                    e.printStackTrace();
                }
            });
        }, 0, monitorExecutorServiceNumberOfIntervals, TimeUnit.SECONDS);
    }

    /**
     *  进行URl访问测试
     * @param unVisitedUrlsModel 需要进行访问的URL数据
     * @param ignoreBlackRecurseHost 是否不递归黑名单限制的域名
     */
    public static void accessUnVisitedUrlsModel(UnVisitedUrlsModel unVisitedUrlsModel, boolean ignoreBlackRecurseHost) {
        if (unVisitedUrlsModel != null){
            //获取URL
            List<String> unvisitedUrls = unVisitedUrlsModel.getUnvisitedUrls();

            //获取这个MsgHash对应的请求体和响应体
            List<String> referHeaders = null;
            String msgHash = unVisitedUrlsModel.getMsgHash();
            ReqMsgDataModel reqMsgDataModel = ReqMsgDataTable.fetchMsgDataByMsgHash(msgHash);
            if (isEmptyObj(reqMsgDataModel)){
                stderr_println(LOG_ERROR, String.format("[!] fetch MsgData By MsgHash is NuLL: [%s]", msgHash));
            }else {
                //获取请求头作为参考数据
                HelperPlus helperPlus = HelperPlus.getInstance();
                referHeaders = helperPlus.getHeaderList(true, reqMsgDataModel.getReqBytes());
            }

            //记录准备加入的请求
            List<String> finalReferHeaders = referHeaders;
            for (String reqUrl:unvisitedUrls){
                if (urlScanRecordMap.get(reqUrl) <= 0){
                    //记录已访问的URL
                    urlScanRecordMap.add(reqUrl); //防止循环扫描

                    // Check 记录URL已经扫描 不一定合适,因为没有扫描的URL很难处理
                    RecordUrlTable.insertOrUpdateAccessedUrl(reqUrl,299);

                    //不递归扫描黑名单内的主机 //需要 放在记录URL后面 不然每次都会获取到这个目标 导致无法忽略正常扫描
                    if (ignoreBlackRecurseHost && isContainOneKey(reqUrl, CONF_NOT_AUTO_RECURSE, false)){
                        continue;
                    }

                    //记录总请求数增加
                    totalRequestCount += 1;
                    try {
                        //发起HTTP请求
                        stdout_println(LOG_DEBUG, String.format("[*] Auto Access URL: %s", reqUrl));
                        IHttpRequestResponse requestResponse = BurpHttpUtils.makeHttpRequestForGet(reqUrl, finalReferHeaders);
                        if (requestResponse != null) {
                            HttpMsgInfo msgInfo = new HttpMsgInfo(requestResponse);
                            //更新所有有响应的主动访问请求URL记录到数据库中
                            RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);

                            //加入请求分析列表
                            if (msgInfo.getRespInfo().getRespLength()>0)
                                insertOrUpdateReqDataAndReqMsgData(msgInfo,"Auto");

                            //保存网站相关的所有 PATH, 便于后续path反查的使用 当响应状态 In [200 | 403 | 405] 说明路径存在
                            if(autoRecordPathIsOpen
                                    && isEqualsOneKey(msgInfo.getRespStatusCode(), CONF_ALLOW_RECORD_STATUS, false)
                                    && !msgInfo.getUrlInfo().getPathToDir().equals("/")
                                    && !isContainOneKey(msgInfo.getUrlInfo().getUrlToFileUsual(), CONF_NOT_AUTO_RECORD, false)
                                    && !isContainOneKey(msgInfo.getRespInfo().getRespTitle(), CONF_NOT_RECORD_TITLE, false)
                            ){
                                enhanceRecordPathFilter(msgInfo, dynamicPthFilterIsOpen);
                            }

                        }
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        stderr_println(LOG_ERROR, String.format("Thread.sleep Error: %s", e.getMessage()));
                        e.printStackTrace();
                    }
                }
            }
            //标记数据为空 如果很多都没扫描的话,就不要清理了,影响实际使用
            if (!ignoreBlackRecurseHost)
                AnalyseResultTable.clearUnVisitedUrlsByMsgHash(msgHash);
        }
    }

    /**
     * 重复使用的独立的 path to url 路径计算+更新函数
     * @param findPathModel
     */
    private void pathsToUrlsByPathTree(FindPathModel findPathModel) {
        if (findPathModel != null) {
            int id = findPathModel.getId();
            String reqUrl = findPathModel.getReqUrl();
            String reqHostPort = findPathModel.getReqHostPort();
            JSONArray findPathArray = findPathModel.getFindPath();

            // 从数据库中获取当前 reqHostPort 的 PathTree
            PathTreeModel pathTreeModel = PathTreeTable.fetchPathTreeByReqHostPort(reqHostPort);
            //如果 PATH TREE都没有添加过, pathTreeModel 就是空的
            if (pathTreeModel == null){
                //如果 PATH TREE 不应该是空的,因为任务二已经添加过了,
                stderr_println(LOG_ERROR, String.format("[!] 获取 HOST [host:%s] 对应的 PathTree 失败!!! 可能需要手动生成PathTree!!!", reqHostPort));
                return;
            }

            Integer currBasicPathNum = pathTreeModel.getBasicPathNum();
            JSONObject currPathTree = pathTreeModel.getPathTree();
            // 基于根树和paths列表计算新的字典
            //当获取到Path数据,并且路径树不为空时 可以计算新的URL列表
            if (isNotEmptyObj(findPathArray)
                    && isNotEmptyObj(currPathTree)
                    && isNotEmptyObj(currPathTree.getJSONObject("ROOT"))
            ) {
                List<String> findUrlsList = new ArrayList<>();
                //遍历路径列表,开始进行查询
                String reqBaseUrl = new HttpUrlInfo(reqUrl).getUrlToFileUsual();

                for (Object findPath: findPathArray){
                    JSONArray nodePath = PathTreeUtils.findNodePathInTree(currPathTree, (String) findPath);
                    //查询到结果就组合成URL,加到查询结果中
                    if (isNotEmptyObj(nodePath)){
                        for (Object prefix:nodePath){
                            //组合URL、findNodePath、path
                            String prefixPath = (String) prefix;
                            prefixPath = prefixPath.replace("ROOT", reqBaseUrl);
                            String findUrl = AnalyseInfoUtils.concatUrlAddPath(prefixPath, (String) findPath);
                            findUrlsList.add(findUrl);
                        }
                    }
                }

                // 去重、格式化、过滤 不符合规则的URL
                findUrlsList = AnalyseInfo.filterFindUrls(reqUrl, findUrlsList, BurpExtender.onlyScopeDomain);

                if (findUrlsList.size() > 0){
                    //判断查找到的URL是全新的
                    //1、获取所有 id 对应的原始 findUrlsList
                    DynamicUrlsModel dynamicUrlsModel = AnalyseResultTable.fetchDynamicUrlsDataById(id);
                    List<String> rawPathToUrls = dynamicUrlsModel.getPathToUrls();

                    //2、计算新找到的URl的数量
                    List<String> newAddUrls = CastUtils.listReduceList(findUrlsList, rawPathToUrls);
                    if (newAddUrls.size()>0){
                        //3、将当前新找到的URL合并更新
                        dynamicUrlsModel.setPathToUrls(CastUtils.listAddList(findUrlsList, rawPathToUrls));
                        List<String> rawUnvisitedUrls = dynamicUrlsModel.getUnvisitedUrls();
                        dynamicUrlsModel.setUnvisitedUrls(CastUtils.listAddList(rawUnvisitedUrls, newAddUrls));
                        dynamicUrlsModel.setBasicPathNum(currBasicPathNum);

                        //更新动态的URL数据
                        int apiDataIndex = AnalyseResultTable.updateDynamicUrlsModel(dynamicUrlsModel);
                        //if (apiDataIndex > 0)
                        // stdout_println(LOG_DEBUG, String.format("[+] New UnvisitedUrls: addUrls:[%s] + rawUrls:[%s] -> newUrls:[%s]",
                        // newAddUrls.size(),rawUnvisitedUrls.size(),dynamicUrlsModel.getUnvisitedUrls().size()));
                    } else {
                        // 没有找到新路径时,仅需要更新基础计数即可
                        AnalyseResultTable.updateDynamicUrlsBasicNum(id, currBasicPathNum);
                    }
                } else {
                    // 没有找到新路径时,仅需要更新基础计数即可
                    AnalyseResultTable.updateDynamicUrlsBasicNum(id, currBasicPathNum);
                }
            }
        }
    }

    /**
     * 监听线程关闭函数
     */
    public static void shutdownMonitorExecutor() {
        // 关闭监控线程池
        if (monitorExecutor != null && !monitorExecutor.isShutdown()) {
            monitorExecutor.shutdown();
            try {
                // 等待线程池终止，设置一个合理的超时时间
                if (!monitorExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    // 如果线程池没有在规定时间内终止，则强制关闭
                    monitorExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                // 如果等待期线程被中断，恢复中断状态
                Thread.currentThread().interrupt();
                // 强制关闭
                monitorExecutor.shutdownNow();
            }
        }
    }



}
