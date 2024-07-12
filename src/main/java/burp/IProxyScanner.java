package burp;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import database.*;
import model.*;
import ui.ConfigPanel;
import utils.CastUtils;
import utils.InfoAnalyseUtils;
import utils.PathTreeUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;

import static burp.BurpExtender.*;
import static database.PathTreeTable.fetchPathTreeByReqHostPort;
import static database.PathTreeTable.insertOrUpdatePathTree;
import static database.RecordPathTable.fetchAllNotAddToTreeRecords;
import static utilbox.UrlUtils.getBaseUrlNoDefaultPort;
import static utils.BurpPrintUtils.*;
import static utils.ElementUtils.isContainOneKey;
import static utils.ElementUtils.isEqualsOneKey;
import static utils.PathTreeUtils.genPathsTree;


public class IProxyScanner implements IProxyListener {
    private int totalScanCount = 0; //记录所有经过插件的URL数量

    private static final int MaxRespBodyLen = 200000; //最大支持处理的响应
    public static RecordHashMap urlScanRecordMap = new RecordHashMap(); //记录已加入扫描列表的URL Hash
    public static RecordHashMap urlPathRecordMap = new RecordHashMap(); //记录已加入待分析记录的URL Path Dir

    final ThreadPoolExecutor executorService;
    static ScheduledExecutorService monitorExecutor;
    private static int monitorExecutorServiceNumberOfIntervals = 2;


    public IProxyScanner() {
        // 获取操作系统内核数量
        int availableProcessors = Runtime.getRuntime().availableProcessors();
        int coreCount = Math.min(availableProcessors, 16);
        int maxPoolSize = coreCount * 2;

        // 高性能模式
        monitorExecutorServiceNumberOfIntervals = (availableProcessors > 6) ? 1 : monitorExecutorServiceNumberOfIntervals;
        long keepAliveTime = 60L;

        // 创建一个足够大的队列来处理您的任务
        BlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>(10000);

        executorService = new ThreadPoolExecutor(
                coreCount,
                maxPoolSize,
                keepAliveTime,
                TimeUnit.SECONDS,
                workQueue,
                Executors.defaultThreadFactory(),
                new ThreadPoolExecutor.AbortPolicy() // 当任务太多时抛出异常，可以根据需要调整策略
        );
        stdout_println(LOG_INFO,"[+] run executorService maxPoolSize: " + coreCount + " ~ " + maxPoolSize + ", monitorExecutorServiceNumberOfIntervals: " + monitorExecutorServiceNumberOfIntervals);

        monitorExecutor = Executors.newSingleThreadScheduledExecutor();

        startDatabaseMonitor();
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, final IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!messageIsRequest) {
            //记录并更新UI面板中的扫描计数
            totalScanCount += 1;
            ConfigPanel.lbRequestCount.setText(String.valueOf(totalScanCount));

            //解析当前请求的信息
            HttpMsgInfo msgInfo = new HttpMsgInfo(iInterceptedProxyMessage);
            String respStatusCodeString = String.valueOf(msgInfo.getRespStatusCode());

            //看URL识别是否报错 不记录报错情况
            if (msgInfo.getUrlInfo().getReqBaseUrl() == null ||msgInfo.getUrlInfo().getReqBaseUrl().equals("-")){
                stdout_println(LOG_ERROR,"[-] URL转化失败 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            //匹配黑名单域名 黑名单域名相关的文件和路径都是无用的
            if(isContainOneKey(msgInfo.getUrlInfo().getReqHost(), CONF_BLACK_URL_HOSTS, false)){
                stdout_println(LOG_DEBUG,"[-] 匹配黑名单域名 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            //判断是否是正常的响应 不记录无响应情况
            if (msgInfo.getRespBytes() == null || msgInfo.getRespBytes().length == 0) {
                stdout_println(LOG_DEBUG,"[-] 没有响应内容 跳过插件处理：" + msgInfo.getReqUrl());
                return;
            }

            //更新所有有响应的主动访问请求URL记录到数据库中
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    //记录请求记录到数据库中（记录所有请求）
                    RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);
                }
            });

            //保存网站相关的所有 PATH, 便于后续path反查的使用 当响应状态 In [200 | 403 | 405] 说明路径存在
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    if(urlPathRecordMap.get(msgInfo.getUrlInfo().getReqBaseDir()) <= 0
                            && isEqualsOneKey(respStatusCodeString, CONF_NEED_RECORD_STATUS, true)
                            && !msgInfo.getUrlInfo().getReqPath().equals("/")){
                        RecordPathTable.insertOrUpdateSuccessUrl(msgInfo);
                        urlPathRecordMap.add(msgInfo.getUrlInfo().getReqBaseDir());
                        //stdout_println(LOG_DEBUG, String.format("[+] Record ReqBasePath: %s -> %s", msgInfo.getUrlInfo().getReqBaseDir(), msgInfo.getRespStatusCode()));
                    }
                }
            });

            // 排除黑名单后缀 ||  排除黑名单路径 "jquery.js|xxx.js" 这些JS文件是通用的、无价值的、
            if(isEqualsOneKey(msgInfo.getUrlInfo().getReqPathExt(), CONF_BLACK_URL_EXT, false) ||
                    isContainOneKey(msgInfo.getUrlInfo().getReqPath(), CONF_BLACK_URL_PATH, false)){
                //stdout_println(LOG_DEBUG, "[-] 匹配黑名单后缀|路径 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            // 看status是否为30开头 || 看status是否为4  403 404 30x 都是没有敏感数据和URl的,可以直接忽略
            if (respStatusCodeString.startsWith("3") || respStatusCodeString.startsWith("4")){
                //stdout_println(LOG_DEBUG, "[-] 匹配30X|404 页面 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            //记录准备加入的请求
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    //判断URL是否已经扫描过
                    if (urlScanRecordMap.get(msgInfo.getMsgHash()) <= 0) {
                        //防止响应体过大
                        byte[] respBytes = msgInfo.getRespBytes().length > MaxRespBodyLen ? Arrays.copyOf(msgInfo.getRespBytes(), MaxRespBodyLen) : msgInfo.getRespBytes();
                        msgInfo.setRespBytes(respBytes);
                        //加入请求列表
                        int msgId = iInterceptedProxyMessage.getMessageReference();
                        insertOrUpdateReqDataAndReqMsgData(msgInfo, msgId, "Proxy");

                        //放到后面,确保已经记录数据,不然会被过滤掉
                        urlScanRecordMap.add(msgInfo.getMsgHash());
                    }
                }
            });
        } else {
            //解析当前请求的信息
            HttpMsgInfo msgInfo = new HttpMsgInfo(iInterceptedProxyMessage);

            //看URL识别是否报错  || 是否匹配黑名单域名
            if (msgInfo.getUrlInfo().getReqBaseUrl() == null ||
                    msgInfo.getUrlInfo().getReqBaseUrl().equals("-") ||
                    isContainOneKey(msgInfo.getUrlInfo().getReqHost(), CONF_BLACK_URL_HOSTS, false)
            ) return;

            //记录所有主动访问请求记录到数据库中
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    //记录请求记录到数据库中（记录所有请求）
                    RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);
                    //Todo:解决记录URL和访问URL不一致的问题
                    // 显示URL  https://www.am-liaotian.com/chat/chatClient/chatbox.jsp?companyID=8994&configID=15&k=1
                    // 记录URL  https://www.am-liaotian.com:443/chat/chatClient/chatbox.jsp?companyID=8994&configID=15&k=1
                }
            });

/*
            //加载sitemap中已经访问过的URL到数据库中 针对每个主机需要执行一次
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    String reqPrefix = msgInfo.getUrlInfo().getReqPrefix();
                    String reqHostPort = msgInfo.getUrlInfo().getReqHostPort();
                    //判断当前前缀开头的所有URL是否已经已经被记录到内存中
                    if (urlPathRecordMap.get(reqPrefix) <= 0){
                        urlPathRecordMap.add(reqPrefix);
                        //把当前前缀的URl + 999 状态码 作为标记,插入到数据库中, 如果已存在表示这个sitemap数据都已经加入成功
                        if (RecordUrlTable.insertOrUpdateAccessedUrl(reqPrefix, reqHostPort, 999) > 0)
                            BurpSitemapUtils.addSiteMapUrlsToDB(reqPrefix, false);
                    }
                }
            });
*/

        }
    }

    /**
     * 合并添加请求数据和请求信息为一个函数
     * @param msgInfo
     * @param msgId
     */
    private void insertOrUpdateReqDataAndReqMsgData(HttpMsgInfo msgInfo, int msgId, String reqSource) {
        //存储请求体|响应体数据
        int msgDataIndex = ReqMsgDataTable.insertOrUpdateMsgData(msgInfo);
        if (msgDataIndex > 0){
            // 存储到URL表
            int insertOrUpdateOriginalDataIndex = ReqDataTable.insertOrUpdateReqData(msgInfo, msgId, msgDataIndex, reqSource);
            if (insertOrUpdateOriginalDataIndex > 0)
                stdout_println(LOG_INFO, String.format("[+] Success Add Task: %s -> msgHash: %s -> reqSource:%s",
                        msgInfo.getReqUrl(), msgInfo.getMsgHash(), reqSource));
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

                    //任务1、获取需要解析的响应体数据并进行解析响
                    int needHandledReqDataId = ReqDataTable.fetchUnhandledReqDataId(true);
                    if (needHandledReqDataId > 0){
                        //获取 msgDataIndex 对应的数据
                        ReqMsgDataModel msgData = ReqMsgDataTable.fetchMsgDataById(needHandledReqDataId);
                        if (msgData != null){
                            HttpMsgInfo msgInfo =  new HttpMsgInfo(
                                    msgData.getReqUrl(),
                                    msgData.getReqBytes(),
                                    msgData.getRespBytes(),
                                    msgData.getMsgHash()
                            );

                            //进行数据分析
                            AnalyseResult analyseResult = InfoAnalyse.analyseMsgInfo(msgInfo);

                            //存入分析结果
                            if(!analyseResult.getInfoList().isEmpty() || !analyseResult.getPathList().isEmpty() || !analyseResult.getUrlList().isEmpty()){
                                //将初次分析结果写入数据库
                                int analyseDataIndex = AnalyseResultTable.insertBasicAnalyseResult(msgInfo, analyseResult);
                                if (analyseDataIndex > 0){
                                    stdout_println(LOG_INFO, String.format("[+] 分析结果已写入: %s -> msgHash: %s", msgInfo.getReqUrl(), msgInfo.getMsgHash()));
                                }

                                //将爬取到的 URL 加入到 RecordPathTable
                                for (String url:analyseResult.getUrlList())
                                    RecordPathTable.insertOrUpdateSuccessUrl(url,200);
                            }
                        }
                        return;
                    }

                    //任务2、如果没有需要分析的数据,就更新Path树信息 为动态 path to url 做准备
                    int unhandledReqDataId = ReqDataTable.fetchUnhandledReqDataId(false);
                    if (unhandledReqDataId <= 0){
                        //获取需要更新的所有URL记录
                        JSONArray recordUrls = fetchAllNotAddToTreeRecords();
                        if (!recordUrls.isEmpty()){
                            for (Object record : recordUrls) {
                                //生成新的路径树
                                JSONObject addedTreeObj = genPathsTree((JSONObject) record);
                                if (addedTreeObj != null && !addedTreeObj.isEmpty()){
                                    //合并|插入新的路径树
                                    int pathTreeIndex = insertOrUpdatePathTree(addedTreeObj);
//                                    if (pathTreeIndex > 0) {
//                                        stdout_println(LOG_INFO, String.format("[+] Path Tree 更新成功: %s",addedTreeObj.toJSONString()));
//                                    }
                                }
                            }
                            //更新数据后先返回,优先进行之前的操作
                            return;
                        }
                    }

                    // TODO 优化语句 实现兼容 find_path_num>0 + 状态 [ANALYSE_ING|ANALYSE_END] + B.basic_path_num > A.basic_path_num
                    //任务3、判断是否存在未处理的Path路径,没有的话就根据树生成计算新的URL
                    int unhandledRecordPathId = RecordPathTable.fetchUnhandledRecordPathId();
                    if (unhandledRecordPathId <= 0) {
                        //获取一条需要分析的数据 状态为待解析
                        FindPathModel findPathModel = AnalyseResultTable.fetchUnhandledPathData();

                        //如果没有获取成功, 就获取 基准路径树 小于 PathTree基准的数据进行更新
                        if (findPathModel == null){
                            findPathModel = UnionTableSql.fetchOneNeedUpdatedPathToUrlData();
                        }

                        if (findPathModel != null) {
                            pathsToUrlsByPathTree(findPathModel);
                            return;
                        }
                    }

                    //todo: 增加自动递归查询功能

                    //todo: UI完善全局变量内容的更新
                } catch (Exception e) {
                    stderr_println(String.format("[!] scheduleAtFixedRate error: %s", e.getMessage()));
                    e.printStackTrace();
                }
            });
        }, 0, monitorExecutorServiceNumberOfIntervals, TimeUnit.SECONDS);
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
            PathTreeModel pathTreeModel = fetchPathTreeByReqHostPort(reqHostPort);
            int currBasicPathNum = pathTreeModel.getBasicPathNum();
            JSONObject currPathTree = pathTreeModel.getPathTree();

            // 基于根树和paths列表计算新的字典
            //当获取到Path数据,并且路径树不为空时 可以计算新的URL列表
            if (findPathArray != null && !findPathArray.isEmpty()
                    && currPathTree != null && !currPathTree.isEmpty()
                    && !((JSONObject) currPathTree.get("ROOT")).isEmpty())
            {
                List<String> findUrlsList = new ArrayList<>();
                //遍历路径列表,开始进行查询
                String reqBaseUrl = getBaseUrlNoDefaultPort(reqUrl);

                for (Object findPath: findPathArray){
                    JSONArray nodePath = PathTreeUtils.findNodePathInTree(currPathTree, (String) findPath);
                    //查询到结果就组合成URL,加到查询结果中
                    if (nodePath != null && !nodePath.isEmpty()){
                        for (Object prefix:nodePath){
                            //组合URL、findNodePath、path
                            String prefixPath = (String) prefix;
                            prefixPath = prefixPath.replace("ROOT", reqBaseUrl);
                            String findUrl = InfoAnalyseUtils.concatUrlAddPath(prefixPath, (String) findPath);
                            findUrlsList.add(findUrl);
                        }
                    }
                }

                // 去重和过滤 不符合规则的URL
                findUrlsList = InfoAnalyse.filterFindUrls(reqUrl, findUrlsList, false);

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

                        int apiDataIndex = AnalyseResultTable.updateDynamicUrlsModel(dynamicUrlsModel);
/*
                        if (apiDataIndex > 0)
                            stdout_println(LOG_DEBUG, String.format(
                                    "[+] PATH To URL存在新结果: \n" +
                                            "newAddUrls:[%s], currBasicPathNum:[%s]" +
                                            "rawPathToUrls:[%s] ,  newPathToUrls:[%s] " +
                                            "rawUnvisitedUrls:[%s] , newUnvisitedUrls:[%s]",
                                    newAddUrls.size(), dynamicUrlsModel.getBasicPathNum(),
                                    rawPathToUrls.size(), dynamicUrlsModel.getPathToUrls(),
                                    rawUnvisitedUrls.size(),dynamicUrlsModel.getUnvisitedUrls()
                            ));
*/
                    } else {
                        // 没有找到新路径时,仅需要更新基础计数即可
                        AnalyseResultTable.updateDynamicUrlsBasicNumById(id, currBasicPathNum);
                    }
                } else {
                    // 没有找到新路径时,仅需要更新基础计数即可
                    AnalyseResultTable.updateDynamicUrlsBasicNumById(id, currBasicPathNum);
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
