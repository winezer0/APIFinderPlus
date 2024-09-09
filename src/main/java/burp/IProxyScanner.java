package burp;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import database.*;
import model.*;
import ui.BasicHostConfigPanel;
import ui.BasicUrlConfigPanel;
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

    public static RecordHashMap urlScanRecordMap = new RecordHashMap(); //记录已加入扫描列表的URL 防止重复扫描

    public static ThreadPoolExecutor executorService = null;
    public static ScheduledExecutorService monitorExecutor;

    //响应体进行正则分割时的默认大小
    public static int maxPatterChunkSize;
    //最大支持存储的响应 比特长度
    public static int maxStoreRespBodyLen;
    //自动处理任务的时间频率,性能越低,频率越应该慢
    public static int monitorExecutorIntervals;
    //是否启用增强的path过滤模式 //需要设置默认关闭,暂时功能没有完善、对于URL无法访问的情况没有正常处理、导致卡顿
    public static boolean dynamicPathFilterIsOpen;
    //是否启用自动记录每个请求的PATH //自动记录功能应该开启,不然没有pathTree生成
    public static boolean autoRecordPathIsOpen;
    //是否进行自动PathTree生成URL
    public static boolean autoPathsToUrlsIsOpen;
    //是否进行递归URL扫描
    public static boolean autoRecursiveIsOpen;
    //开关插件的监听功能
    public static boolean proxyListenIsOpen;
    //自动刷新未访问URL的功能
    public static boolean autoRefreshUnvisitedIsOpen;
    //自动刷新UI的功能
    public static boolean autoRefreshUiIsOpen;

    //存储每个host的动态响应对比关系
    public static Map<String, Map<String,Object>> urlCompareMap = new HashMap<>();
    //在动态响应对比关系生成前,需要把响应信息先存起来,等后续再进行处理
    private static ConcurrentHashMap<String, Map<String,Object>> waitingUrlCompareMap = new ConcurrentHashMap<>();
    //持久化保存对象的Hash
    private String urlCompareMapCacheFile = String.format("%s.urlCompareMap.json", configName);
    private String urlCompareMapHistoryHash = null;

    //设置最大进程数量
    private int maxPoolSize;

    public IProxyScanner() {
        //开关的 默认值配置
        maxPatterChunkSize = maxPatterChunkSizeDefault;
        maxStoreRespBodyLen = maxStoreRespBodyLenDefault;
        monitorExecutorIntervals = monitorExecutorIntervalsDefault;
        dynamicPathFilterIsOpen = dynamicPathFilterIsOpenDefault;
        autoRecordPathIsOpen  = autoRecordPathIsOpenDefault;
        autoPathsToUrlsIsOpen = autoPathsToUrlsIsOpenDefault;
        autoRecursiveIsOpen = autoRecursiveIsOpenDefault;
        proxyListenIsOpen = proxyListenIsOpenDefault;
        autoRefreshUnvisitedIsOpen = autoRefreshUnvisitedIsOpenDefault;
        autoRefreshUiIsOpen = autoRefreshUiIsOpenDefault;

        //加载缓存过滤器
        urlCompareMap = BurpFileUtils.LoadJsonFromFile(urlCompareMapCacheFile);
        // 获取操作系统内核数量
        int availableProcessors = Runtime.getRuntime().availableProcessors();
        int coreCount = Math.min(availableProcessors, 16);
        maxPoolSize = coreCount * 2;
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
        stdout_println(LOG_INFO,"[+] run executor maxPoolSize: " + coreCount + " ~ " + maxPoolSize + ", monitorExecutorIntervals: " + monitorExecutorIntervals);

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
            BasicUrlConfigPanel.lbRequestCountOnUrl.setText(String.valueOf(totalRequestCount));
            BasicHostConfigPanel.lbRequestCountOnHost.setText(String.valueOf(totalRequestCount));

            //解析当前请求的信息
            HttpMsgInfo msgInfo = new HttpMsgInfo(iInterceptedProxyMessage);
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
                    && !msgInfo.getUrlInfo().getPathToDir().equals("/")  //忽略没有目录的选项
                    && isEqualsOneKey(msgInfo.getRespStatusCode(), CONF_WHITE_RECORD_PATH_STATUS, false) //保留200|403等响应码的路径
                    && !isContainOneKey(msgInfo.getUrlInfo().getUrlToFileUsual(), CONF_BLACK_AUTO_RECORD_PATH, false) //忽略禁止自动进行有效PATH记录的目标
                    && !isContainOneKey(msgInfo.getRespInfo().getRespTitle(), CONF_BLACK_RECORD_PATH_TITLE, false) //忽略禁止自动进行有效PATH记录的响应标题
            ){
                executorService.submit(() -> enhanceRecordPathFilter(msgInfo, dynamicPathFilterIsOpen));
            }

            executorService.submit(() -> {
                //更新所有有响应的主动访问请求URL记录到数据库中  //记录请求记录到数据库中（记录所有请求）
                RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);
            });

            //判断URL是否已经扫描过
            if (urlScanRecordMap.get(rawUrlUsual) <= 0) {
                //应该放到后面,确保已经记录数据,不然会被过滤掉
                urlScanRecordMap.add(rawUrlUsual);
                executorService.submit(() -> {
                    //加入请求列表
                    insertOrUpdateReqDataAndReqMsgData(msgInfo,"Right");
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
            BasicUrlConfigPanel.lbRequestCountOnUrl.setText(String.valueOf(totalRequestCount));
            BasicHostConfigPanel.lbRequestCountOnHost.setText(String.valueOf(totalRequestCount));

            //解析当前请求的信息
            HttpMsgInfo msgInfo = new HttpMsgInfo(iInterceptedProxyMessage);
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
                    && !msgInfo.getUrlInfo().getPathToDir().equals("/")  //忽略没有目录的选项
                    && isEqualsOneKey(msgInfo.getRespStatusCode(), CONF_WHITE_RECORD_PATH_STATUS, false) //保留200|403等响应码的路径
                    && !isContainOneKey(msgInfo.getUrlInfo().getUrlToFileUsual(), CONF_BLACK_AUTO_RECORD_PATH, false) //忽略禁止自动进行有效PATH记录的目标
                    && !isContainOneKey(msgInfo.getRespInfo().getRespTitle(), CONF_BLACK_RECORD_PATH_TITLE, false) //忽略禁止自动进行有效PATH记录的响应标题
            ){
                executorService.submit(() -> enhanceRecordPathFilter(msgInfo, dynamicPathFilterIsOpen));
            }

            // 排除黑名单后缀 ||  排除黑名单路径 "jquery.js|xxx.js" 这些JS文件是通用的、无价值的、
            if(isEqualsOneKey(msgInfo.getUrlInfo().getSuffix(), CONF_BLACK_URL_EXT, false)
                    || isContainOneKey(msgInfo.getUrlInfo().getPathToFile(), CONF_BLACK_URL_PATH, false))
            {
                //stdout_println(LOG_DEBUG, "[-] 匹配黑名单后缀|路径 跳过url识别：" + rawUrlUsual);
                return;
            }

            executorService.submit(() -> {
                //更新所有有响应的主动访问请求URL记录到数据库中  //记录请求记录到数据库中（记录所有请求）
                RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);
            });

            // 看status是否为30开头 || 看status是否为4  403 404 30x 都是没有敏感数据和URl的,可以直接忽略
            if (String.valueOf(msgInfo.getRespStatusCode()).startsWith("3") || String.valueOf(msgInfo.getRespStatusCode()).startsWith("4")){
                //stdout_println(LOG_DEBUG, "[-] 匹配30X|404 页面 跳过url识别：" + rawUrlUsual);
                return;
            }

            //判断URL是否已经扫描过
            if (urlScanRecordMap.get(rawUrlUsual) <= 0) {
                //应该放到后面,确保已经记录数据,不然会被过滤掉
                urlScanRecordMap.add(rawUrlUsual);
                executorService.submit(() -> {
                    //加入请求列表
                    insertOrUpdateReqDataAndReqMsgData(msgInfo,"Proxy");
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

            executorService.submit(() -> {
                //记录请求记录到数据库中（记录所有请求）
                RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);
            });
        }
    }

    /**
     * 增强的有效路径判断过滤函数
     */
    public static void enhanceRecordPathFilter(HttpMsgInfo msgInfo, boolean openDynamicFilter) {
        if (!openDynamicFilter){
            executorService.submit(() -> {
                //保存网站相关的所有 PATH, 便于后续path反查的使用 当响应状态 In [200 | 403 | 405] 说明路径存在 方法不准确, 暂时关闭
                RecordPathTable.insertOrUpdateRecordPath(msgInfo);
                stdout_println(LOG_DEBUG, String.format("[*] Direct Record req Base Url: %s", msgInfo.getUrlInfo().getUrlToPathUsual()));
            });
        } else {
            String reqRootUrl = msgInfo.getUrlInfo().getRootUrlUsual();
            String reqUrlToFile = msgInfo.getUrlInfo().getUrlToFileUsual();
            //首先转换为响应Map
            Map<String, Object> respFieldsMap = new RespFieldsModel(msgInfo.getRespInfo()).getAllFieldsAsMap();

            //如果还没有生成对应的过滤条件
            if (!urlCompareMap.containsKey(reqRootUrl)){
                //存储未进行对比的目标,后续通过定时任务再进行对比
                waitingUrlCompareMap.put(reqUrlToFile, respFieldsMap);
                //记录状态为正在生成,避免重复调用 GenerateDynamicFilterMap
                urlCompareMap.put(reqRootUrl, null);
                executorService.submit(() -> {
                    //计算动态过滤条件
                    Map<String, Object> filterModel = RespFieldCompareutils.generateDynamicFilterMap(msgInfo, true);
                    urlCompareMap.put(reqRootUrl, filterModel);
                });
            } else {
                Map<String, Object> currentFilterMap = urlCompareMap.get(reqRootUrl);
                //如果正在生成过滤条件
                if (currentFilterMap == null){
                    //存储未进行对比的目标,后续通过定时任务再进行对比
                    waitingUrlCompareMap.put(reqUrlToFile, respFieldsMap);
                } else {
                    //如果已经生成过滤条件 //当存在对比规则的时候,就进行对比,没有规则，说明目录猜不出来,只能人工添加
                    executorService.submit(() -> {
                        //插入数据库记录 当过滤条件为空时直接插入路径、过滤条件不为空时,就保存所有正常状态的结果
                        if (currentFilterMap.isEmpty() || !RespFieldCompareutils.sameFieldValueIsEquals(respFieldsMap, currentFilterMap, false)) {
                            RecordPathTable.insertOrUpdateRecordPath(msgInfo);
                            stdout_println(LOG_DEBUG, String.format("[+] Dynamic Compare Record req Base Url: %s", msgInfo.getUrlInfo().getUrlToPathUsual()));
                        }
                    });
                }
            }
        }
    }

    /**
     * 合并添加请求数据和请求信息为一个函数
     */
    private static void insertOrUpdateReqDataAndReqMsgData(HttpMsgInfo msgInfo, String reqSource) {
        //防止响应体过大
        if (msgInfo.getRespBytes().length > maxStoreRespBodyLen){
            byte[] respBytes = Arrays.copyOf(msgInfo.getRespBytes(), maxStoreRespBodyLen);
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

                    //定时清理URL记录表 防止无用数据占用空间过大
                    if (CommonFetchData.fetchTableCounts(RecordUrlTable.tableName) > 500){
                        stdout_println(LOG_INFO, "[*] cleaning the RecordUrlTable");
                        DBService.clearRecordUrlTable();
                    }

                    //存储一下当前的动态过滤器 如果当前实际的过滤map内容和历史存储的内容不一样时,就写入到文件中
                    String currentJsonHash = calcCRC32(CastUtils.toJsonString(urlCompareMap));
                    if (!currentJsonHash.equals(urlCompareMapHistoryHash)){
                        urlCompareMapHistoryHash = currentJsonHash;
                        BurpFileUtils.writeToPluginPathFileNotEx(urlCompareMapCacheFile, CastUtils.toJsonString(urlCompareMap));
                    }

                    //获取需要解析的响应体数据并进行分析 然后插入到URL结果分析表
                    List<Integer> msgDataIndexList = ReqDataTable.fetchMsgDataIndexListByRunStatus(maxPoolSize, Constants.ANALYSE_WAIT);
                    if (msgDataIndexList.size() > 0){
                        //更新对应的ids为检查中 防止其他进程获取这些数据
                        CommonUpdateStatus.updateStatusByMsgDataIndexList(ReqDataTable.tableName, msgDataIndexList, Constants.ANALYSE_ING);

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
                                AnalyseUrlResultModel analyseResult = AnalyseInfo.analyseMsgInfo(msgInfo);
                                //存入分析结果
                                if(isNotEmptyObj(analyseResult.getInfoArray()) || isNotEmptyObj(analyseResult.getPathList()) || isNotEmptyObj(analyseResult.getUrlList())){
                                    //将初次分析结果写入数据库
                                    int analyseDataIndex = AnalyseUrlResultTable.insertOrUpdateBasicAnalyseResult(msgInfo, analyseResult);
                                    if (analyseDataIndex > 0){
                                        stdout_println(LOG_INFO, String.format("[+] Analysis Result Write Success: %s -> %s", msgInfo.getUrlInfo().getRawUrlUsual(), msgInfo.getMsgHash()));
                                    } else {
                                        stderr_println(LOG_ERROR, String.format("[!] Analysis Result Write Error: %s -> %s", msgInfo.getUrlInfo().getRawUrlUsual(), msgInfo.getMsgHash()));
                                    }
                                } else {
                                    //提示没有提取出任何信息的情况 考虑将没有提取成功的情况也写入数据库,实际上可能没啥意义,理论上会更加完整
                                    stdout_println(LOG_DEBUG, String.format("[-] Analysis Result Is NULL: %s -> %s", msgInfo.getUrlInfo().getRawUrlUsual(), msgInfo.getMsgHash()));
                                }
                            }
                        }
                        //更新对应的ids为分析完成,实际上没啥用
                        CommonUpdateStatus.updateStatusByMsgDataIndexList(ReqDataTable.tableName, msgDataIndexList, Constants.ANALYSE_END);
                        return;
                    }

                    // 新增 获取URL分析结果表中的数据，将其加入到HOST分析结果表
                    // 判断 URL分析结果数据表 中 是否存在没有加入到 HOST分析结果表的数据 waiting状态
                    List<String> urlResultMsgHashList = CommonFetchData.fetchMsgHashByRunStatus(AnalyseUrlResultTable.tableName, Constants.ANALYSE_WAIT, maxPoolSize);
                    if (urlResultMsgHashList.size() > 0){
                        //更新对应的ids为检查中 防止其他进程获取这些数据
                        CommonUpdateStatus.updateStatusByMsgHashList(AnalyseUrlResultTable.tableName, urlResultMsgHashList, Constants.ANALYSE_ING);
                        //由于数据不是很大，可以一次性获取需要处理的结果
                        List<AnalyseUrlResultModel> AnalyseUrlResultModels = AnalyseUrlResultTable.fetchUrlResultByMsgHashList(urlResultMsgHashList);
                        //循环插入数据 到HOST结果表
                        for (AnalyseUrlResultModel analyseUrlResultModel : AnalyseUrlResultModels){
                            AnalyseHostResultModel analyseHostResultModel = new AnalyseHostResultModel(analyseUrlResultModel);
                            AnalyseHostResultTable.insertOrUpdateAnalyseHostResult(analyseHostResultModel);
                        }
                        //更新对应的ids为分析完成,实际上没啥用
                        CommonUpdateStatus.updateStatusByMsgHashList(AnalyseUrlResultTable.tableName, urlResultMsgHashList, Constants.ANALYSE_END);
                        return;
                    }

                    //清理在等待动态过滤Map生成过程中没有处理的响应对象
                    if (dynamicPathFilterIsOpen && isNotEmptyObj(waitingUrlCompareMap)){
                        // 创建一个ArrayList来保存所有的键，这是一个安全的迭代方式
                        ArrayList<String> keys = new ArrayList<>(waitingUrlCompareMap.keySet());
                        // 遍历键的列表 对每个缓存目标进行检查,看看对应的URL过滤信息是否已经生成了
                        for (String reqUrl : keys) {
                            Map<String,Object> respFieldsMap = waitingUrlCompareMap.get(reqUrl);
                            String rootUrl = new HttpUrlInfo(reqUrl).getRootUrlUsual();
                            Map<String, Object> currentFilterMap = urlCompareMap.get(rootUrl);
                            if (currentFilterMap != null){
                                waitingUrlCompareMap.remove(reqUrl);
                                if(isNotEmptyObj(currentFilterMap) && !RespFieldCompareutils.sameFieldValueIsEquals(respFieldsMap, currentFilterMap, false)){
                                    int setStatusCode = respFieldsMap.get("StatusCode") == null ? 299: (int) respFieldsMap.get("StatusCode");
                                    RecordPathTable.insertOrUpdateRecordPath(reqUrl, setStatusCode);
                                    stdout_println(LOG_DEBUG, String.format("[+] Insert Temp Record req Base Url: %s", reqUrl));
                                }
                            }else {
                                urlCompareMap.put(rootUrl, new HashMap<>());
                                stdout_println(String.format("[!] 未成功生成[%s]的动态响应过滤关系! 置空处理", rootUrl));
                            }
                        }
                        // 先返回进行其他操作
                        return;
                    }

                    //任务2、从path记录表中读取新增的网站路径，用于更新PathTree信息, 为动态计算 path to url 做准备
                    List<Integer> recordPathIds = CommonFetchData.fetchIdsByRunStatus(RecordPathTable.tableName, Constants.ANALYSE_WAIT, maxPoolSize * 2);
                    if (recordPathIds.size() > 0){
                        //更新对应的ids为检查中 防止其他进程获取这些数据
                        CommonUpdateStatus.updateStatusByIds(RecordPathTable.tableName, recordPathIds, Constants.ANALYSE_ING);
                        //由于数据不是很大，可以一次性获取需要处理的结果
                        List<RecordPathDirsModel> recordPathDirsModels = RecordPathTable.fetchPathRecordsByStatus(Constants.ANALYSE_ING);
                        for (RecordPathDirsModel recordPathModel : recordPathDirsModels) {
                            //根据新增的路径生成路径树
                            PathTreeModel pathTreeModel = PathTreeUtils.genPathsTree(recordPathModel);
                            if (pathTreeModel != null){
                                //合并|插入新的路径树
                                int pathTreeIndex = PathTreeTable.insertOrUpdatePathTree(pathTreeModel);
                                if (pathTreeIndex > 0)
                                    stdout_println(LOG_DEBUG, String.format("[+] Path Tree Update Success: %s",pathTreeModel.getRootUrl()));
                            }
                        }
                        //更新对应的ids为检查完毕
                        CommonUpdateStatus.updateStatusByIds(RecordPathTable.tableName,recordPathIds, Constants.ANALYSE_END);
                    }

                    if (autoPathsToUrlsIsOpen){
                        //任务 获取 基准路径树 小于 PathTree基准的数据进行更新
                        List<FindPathModel> findPathModelList = UnionTableSql.fetchHostTableNeedUpdatePathDataList(maxPoolSize);
                        if (findPathModelList.size()>0){
                            for (FindPathModel findPathModel:findPathModelList) {
                                stdout_println(LOG_DEBUG, String.format("[*] 获取动态更新PATHTree进行重计算 PathNum: %s", findPathModel.getFindPath().size()));
                                findPathsToUrlsByPathTree(findPathModel);
                            }
                            return;
                        }
                    }

                    // 自动递归查询功能
                    if (autoRecursiveIsOpen && executorService.getActiveCount() < 2){
                        //获取一个未访问URL列表
                        executorService.submit(() -> {
                            //将URL访问过程作为一个基本任务外放, 可能会频率过快, 目前没有问题
                            List<UnVisitedUrlsModel> unVisitedUrlsModels =  AnalyseHostUnVisitedUrls.fetchAllUnVisitedUrlsWithLimit(1);
                            for (UnVisitedUrlsModel unVisitedUrlsModel: unVisitedUrlsModels){
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
        }, 0, monitorExecutorIntervals, TimeUnit.SECONDS);
    }

    /**
     *  进行URl访问测试
     * @param unVisitedUrlsModel 需要进行访问的URL数据
     * @param ignoreBlackRecurseHost 是否不递归黑名单限制的域名
     */
    public static void accessUnVisitedUrlsModel(UnVisitedUrlsModel unVisitedUrlsModel, boolean ignoreBlackRecurseHost) {
        if (unVisitedUrlsModel != null){
            //获取URL
            String rootUrl = unVisitedUrlsModel.getRootUrl();
            List<String> unvisitedUrls = unVisitedUrlsModel.getUnvisitedUrls();

            //获取 这个Root URL 对应的最新的 请求体和响应体
            List<String> referHeaders = null;
            ReqMsgDataModel reqMsgDataModel = ReqMsgDataTable.fetchMsgDataByRootUrlDesc(rootUrl);
            if (isEmptyObj(reqMsgDataModel)){
                stderr_println(LOG_ERROR, String.format("[!] fetch MsgData By Like [%s] is NULL", rootUrl));
            } else {
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

                    // 记录URL已经扫描 不一定合适,因为没有扫描的URL很难处理
                    RecordUrlTable.insertOrUpdateAccessedUrl(reqUrl,299);

                    //格式化URL
                    HttpUrlInfo urlInfo = new HttpUrlInfo(reqUrl);

                    //不递归扫描黑名单内的主机 //需要 放在记录URL后面 不然每次都会获取到这个目标 导致无法忽略正常扫描
                    if (ignoreBlackRecurseHost
                            //禁止自动进行未访问URL扫描的目标RootUrl关键字
                            && isContainOneKey(urlInfo.getRootUrlUsual(), CONF_BLACK_AUTO_RECURSE_SCAN, false)
                            //禁止递归访问的URL路径关键字
                            && isContainOneKey(urlInfo.getPathToFile(), CONF_BLACK_RECURSE_REQ_PATH_KEYS, false)
                    ){
                        continue;
                    }

                    //记录总请求数增加
                    totalRequestCount += 1;

                    try {
                        //递归请求参数
                        for (String reqMethod: CONF_RECURSE_REQ_HTTP_METHODS){ //递归请求方法列表
                            for (String reqHttpParam: CONF_RECURSE_REQ_HTTP_PARAMS){ //循环处理请求方法
                                //发起HTTP请求
                                stdout_println(LOG_DEBUG, String.format("[*] Start Request Url: %s <--> %s <--> %s", reqUrl, reqMethod, reqHttpParam));

                                IHttpRequestResponse requestResponse = null;

                                //进行http请求时,先测试连接是否成功
                                if (BurpHttpUtils.AddressCanConnectWithCache(urlInfo)){
                                    //requestResponse = BurpHttpUtils.makeHttpRequest(reqUrl, finalReferHeaders);
                                    //makeHttpRequest(String reqMethod, String reqUrl, List<String> referReqHeaders, byte[] reqBody)
                                    requestResponse  = BurpHttpUtils.makeHttpRequest(reqMethod, reqUrl, reqHttpParam, finalReferHeaders);
                                }

                                if (requestResponse != null) {
                                    HttpMsgInfo msgInfo = new HttpMsgInfo(requestResponse);

                                    //重新更新所有有响应的主动访问请求URL记录到数据库中
                                    RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);

                                    //加入请求分析列表
                                    if (msgInfo.getRespInfo().getRespLength() > 0){
                                        insertOrUpdateReqDataAndReqMsgData(msgInfo,"Auto");
                                    }

                                    //保存网站相关的所有 PATH, 便于后续path反查的使用 当响应状态 In [200 | 403 | 405] 说明路径存在
                                    if(autoRecordPathIsOpen
                                            && !msgInfo.getUrlInfo().getPathToDir().equals("/") //忽略没有目录的选项
                                            && isEqualsOneKey(msgInfo.getRespStatusCode(), CONF_WHITE_RECORD_PATH_STATUS, false) //保留200|403等响应码的路径
                                            && !isContainOneKey(msgInfo.getUrlInfo().getUrlToFileUsual(), CONF_BLACK_AUTO_RECORD_PATH, false) //忽略禁止自动进行有效PATH记录的目标
                                            && !isContainOneKey(msgInfo.getRespInfo().getRespTitle(), CONF_BLACK_RECORD_PATH_TITLE, false)  //忽略禁止自动进行有效PATH记录的响应标题
                                    ){
                                        enhanceRecordPathFilter(msgInfo, dynamicPathFilterIsOpen);
                                    }
                                } else {
                                    stdout_println(LOG_ERROR, String.format("[-] Failed Request Url: %s", reqUrl));
                                }
                            }
                        }
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        stderr_println(LOG_ERROR, String.format("Thread.sleep Error: %s", e.getMessage()));
                        e.printStackTrace();
                    }
                }
            }

            //如果没有配置忽略黑名单主机，表明是右键调用，此时需要强制清空未访问数据
            if (!ignoreBlackRecurseHost){
                AnalyseHostUnVisitedUrls.clearUnVisitedUrlsByRootUrls(Collections.singletonList(rootUrl));
            }
        }
    }

    /**
     * 重复使用的独立的 path to url 路径计算+更新函数
     */
    private void findPathsToUrlsByPathTree(FindPathModel findPathModel) {
        if (findPathModel != null) {
            int findPathId = findPathModel.getId();
            String rootUrl = findPathModel.getRootUrl();
            JSONArray findPathArray = findPathModel.getFindPath();

            //如果没有找到路径, 直接返回
            if (isEmptyObj(findPathArray)) return;

            // 从数据库中获取当前 reqRootUrl 的 PathTree
            PathTreeModel pathTreeModel = PathTreeTable.fetchPathTreeByRootUrl(rootUrl);

            //如果 PATH TREE都没有添加过, pathTreeModel 就是空的
            if (pathTreeModel == null){
                //如果 PATH TREE 不应该是空的,因为任务二已经添加过了,
                stderr_println(LOG_ERROR, String.format("[!] 获取 [%s] 对应的 PathTree 失败!!! 可能需要手动生成PathTree!!!", rootUrl));
                return;
            }
            Integer currBasicPathNum = pathTreeModel.getBasicPathNum();
            JSONObject currPathTree = pathTreeModel.getPathTree();

            // 当路径树不为空 且 不是根目录时 可以计算新的URL列表
            if (isNotEmptyObj(currPathTree) && isNotEmptyObj(currPathTree.getJSONObject("ROOT"))) {
                List<String> findUrlsList = new ArrayList<>();
                //遍历路径列表,开始进行查询
                for (Object findPath: findPathArray){
                    //把路径放在 路径树 中去查找
                    JSONArray nodePath = PathTreeUtils.findNodePathInTree(currPathTree, (String) findPath);

                    //没有查询到,就进行下一次查询
                    if (isEmptyObj(nodePath)) continue;

                    //查询到结果就组合成URL,加到查询结果中
                    for (Object prefix:nodePath){
                        //组合URL、findNodePath、path
                        String prefixPath = (String) prefix;
                        prefixPath = prefixPath.replace("ROOT", rootUrl);
                        String findUrl = AnalyseInfoUtils.concatUrlAddPath(prefixPath, (String) findPath);
                        findUrlsList.add(findUrl);
                    }
                }

                // 去重、格式化、过滤 不符合规则的URL
                findUrlsList = AnalyseInfo.filterFindUrls(rootUrl, findUrlsList, BurpExtender.onlyScopeDomain);
                boolean notHasNewFindUrl = true;
                if (findUrlsList.size() > 0){
                    //判断查找到的URL是全新的
                    //1、获取所有 id 对应的原始 findUrlsList
                    PathToUrlsModel dynamicUrlsModel = AnalyseHostResultTable.fetchDynamicUrlsDataById(findPathId);
                    List<String> rawPathToUrls = dynamicUrlsModel.getPathToUrls();

                    //2、计算新找到的URl的数量
                    List<String> newAddUrls = CastUtils.listReduceList(findUrlsList, rawPathToUrls);
                    if (newAddUrls.size() > 0){
                        //TODO 排除已找到URL中的已访问URL

                        //3、将当前新找到的URL合并更新
                        dynamicUrlsModel.setPathToUrls(CastUtils.listAddList(findUrlsList, rawPathToUrls));
                        List<String> rawUnvisitedUrls = dynamicUrlsModel.getUnvisitedUrls();
                        dynamicUrlsModel.setUnvisitedUrls(CastUtils.listAddList(rawUnvisitedUrls, newAddUrls));
                        dynamicUrlsModel.setBasicPathNum(currBasicPathNum);

                        //4、更新动态的URL数据
                        int apiDataIndex = AnalyseHostResultTable.updateDynamicUrlsDataByModel(dynamicUrlsModel);
                        if (apiDataIndex > 0){
                            notHasNewFindUrl = false; //标记已找到新的URL了
                            stdout_println(LOG_DEBUG, String.format("[+] New UnvisitedUrls: addUrls:[%s] + rawUrls:[%s] -> newUrls:[%s]", newAddUrls.size(),rawUnvisitedUrls.size(),dynamicUrlsModel.getUnvisitedUrls().size()));
                        }
                    }
                }

                // 5、没有找到新路径时,仅需要更新基础计数即可
                if (notHasNewFindUrl) {
                    AnalyseHostResultTable.updateDynamicUrlsBasicNumById(findPathId, currBasicPathNum);
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
