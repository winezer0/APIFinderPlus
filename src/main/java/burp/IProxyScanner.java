package burp;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import database.*;
import model.*;
import ui.ConfigPanel;
import utilbox.HelperPlus;
import utils.BurpHttpUtils;
import utils.CastUtils;
import utils.AnalyseInfoUtils;
import utils.PathTreeUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;

import static burp.BurpExtender.*;
import static utils.BurpPrintUtils.*;
import static utils.ElementUtils.isContainOneKey;
import static utils.ElementUtils.isEqualsOneKey;


public class IProxyScanner implements IProxyListener {
    private int totalRequestCount = 0;  //记录所有经过插件的请求数量
    private static final int MaxRespBodyLen = 200000; //最大支持存储的响应 比特长度

    public static RecordHashMap urlScanRecordMap = new RecordHashMap(); //记录已加入扫描列表的URL Hash
    public static RecordHashMap urlAutoRecordMap = new RecordHashMap(); //记录正在扫描列表的URL

    public static ThreadPoolExecutor executorService = null;
    public static ScheduledExecutorService monitorExecutor;
    private static int monitorExecutorServiceNumberOfIntervals = 2;

    public IProxyScanner() {
        // 获取操作系统内核数量
        int availableProcessors = Runtime.getRuntime().availableProcessors();
        int coreCount = Math.min(availableProcessors, 16);
        int maxPoolSize = coreCount * 2;

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

    @Override
    public void processProxyMessage(boolean messageIsRequest, final IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!messageIsRequest) {
            //记录并更新UI面板中的扫描计数
            totalRequestCount += 1;
            ConfigPanel.lbRequestCount.setText(String.valueOf(totalRequestCount));

            //解析当前请求的信息
            HttpMsgInfo msgInfo = new HttpMsgInfo(iInterceptedProxyMessage);
            String statusCode = String.valueOf(msgInfo.getRespStatusCode());

            //看URL识别是否报错 不记录报错情况
            if (msgInfo.getUrlInfo().getNoParamUrl() == null){
                stdout_println(LOG_ERROR,"[-] URL转化失败 跳过url识别：" + msgInfo.getUrlInfo().getRawUrl());
                return;
            }

            //匹配黑名单域名 黑名单域名相关的文件和路径都是无用的
            if(isContainOneKey(msgInfo.getUrlInfo().getRootUrlUsual(), CONF_BLACK_URL_ROOT, false)){
                stdout_println(LOG_DEBUG,"[-] 匹配黑名单域名 跳过url识别：" + msgInfo.getUrlInfo().getRawUrl());
                return;
            }

            //判断是否是正常的响应 不记录无响应情况
            if (msgInfo.getRespBytes() == null || msgInfo.getRespBytes().length == 0) {
                stdout_println(LOG_DEBUG,"[-] 没有响应内容 跳过插件处理：" + msgInfo.getUrlInfo().getRawUrl());
                return;
            }

            if(ConfigPanel.autoRecordPathIsOpen()
                    && isEqualsOneKey(statusCode, CONF_NEED_RECORD_STATUS, false)
                    && !msgInfo.getUrlInfo().getPath().equals("/")){
                executorService.submit(new Runnable() {
                    @Override
                    public void run() {
                        //保存网站相关的所有 PATH, 便于后续path反查的使用 当响应状态 In [200 | 403 | 405] 说明路径存在 方法不准确, 暂时关闭
                        RecordPathTable.insertOrUpdateRecordPath(msgInfo);
                        stdout_println(LOG_DEBUG, String.format("Record reqBaseUrl: %s", msgInfo.getUrlInfo().getNoFileUrl()));
                    }
                });
            }

            // 排除黑名单后缀 ||  排除黑名单路径 "jquery.js|xxx.js" 这些JS文件是通用的、无价值的、
            if(isEqualsOneKey(msgInfo.getUrlInfo().getExt(), CONF_BLACK_URL_EXT, false) ||
                    isContainOneKey(msgInfo.getUrlInfo().getPath(), CONF_BLACK_URL_PATH, false)){
                //stdout_println(LOG_DEBUG, "[-] 匹配黑名单后缀|路径 跳过url识别：" + msgInfo.getUrlInfo().getReqUrl());
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
                //stdout_println(LOG_DEBUG, "[-] 匹配30X|404 页面 跳过url识别：" + msgInfo.getUrlInfo().getReqUrl());
                return;
            }

            //记录准备加入的请求
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    //判断URL是否已经扫描过
                    if (urlScanRecordMap.get(msgInfo.getMsgHash()) <= 0) {
                        //加入请求列表
                        insertOrUpdateReqDataAndReqMsgData(msgInfo,"Proxy");
                        //放到后面,确保已经记录数据,不然会被过滤掉
                        urlScanRecordMap.add(msgInfo.getMsgHash());
                    }
                }
            });
        } else {
            //解析当前请求的信息
            HttpMsgInfo msgInfo = new HttpMsgInfo(iInterceptedProxyMessage);

            //看URL识别是否报错 //匹配黑名单域名  // 排除黑名单后缀  //排除黑名单路径文件
            if (msgInfo.getUrlInfo().getNoParamUrl() == null
                    ||isContainOneKey(msgInfo.getUrlInfo().getRootUrlUsual(), CONF_BLACK_URL_ROOT, false)
                    ||isEqualsOneKey(msgInfo.getUrlInfo().getExt(), CONF_BLACK_URL_EXT, false)
                    ||isContainOneKey(msgInfo.getUrlInfo().getPath(), CONF_BLACK_URL_PATH, false)
            ){
                return;
            }

            //记录所有主动访问请求记录到数据库中
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
     * 合并添加请求数据和请求信息为一个函数
     * @param msgInfo
     * @param reqSource
     */
    private void insertOrUpdateReqDataAndReqMsgData(HttpMsgInfo msgInfo, String reqSource) {
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
                        msgInfo.getUrlInfo().getRawUrl(), msgInfo.getMsgHash(), reqSource));
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
                    if (UnionTableSql.getTableCounts(RecordUrlTable.tableName)>500){
                        DBService.clearRecordUrlTable();
                        stdout_println(LOG_INFO, "[-] RecordUrlTable 数量超限 开始清理");
                    }

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
                            AnalyseResultModel analyseResult = AnalyseInfo.analyseMsgInfo(msgInfo);

                            //存入分析结果
                            if(!analyseResult.getInfoList().isEmpty()
                                    || !analyseResult.getPathList().isEmpty()
                                    || !analyseResult.getUrlList().isEmpty()){
                                //将初次分析结果写入数据库
                                int analyseDataIndex = AnalyseResultTable.insertBasicAnalyseResult(msgInfo, analyseResult);
                                if (analyseDataIndex > 0){
                                    stdout_println(LOG_INFO, String.format("[+] Analysis Result Write Success: %s -> %s", msgInfo.getUrlInfo().getRawUrl(), msgInfo.getMsgHash()));
                                }

                                //将爬取到的 URL 加入到 RecordPathTable, 不一定准确, 还是得访问一边再说
                                //if (IProxyScanner.autoRecordPath){ RecordPathTable.batchInsertOrUpdateSuccessUrl(analyseResult.getUrlList(), 299); }
                            }
                        }
                        return;
                    }

                    //任务2、如果没有需要分析的数据,就更新Path树信息 为动态 path to url 做准备
                    int unhandledReqDataId = ReqDataTable.fetchUnhandledReqDataId(false);
                    if (unhandledReqDataId <= 0){
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
                    }

                    // 兼容 find_path_num>0 + 状态 [ANALYSE_ING|ANALYSE_END] + B.basic_path_num > A.basic_path_num
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

                    // 增加自动递归查询功能
                    if (ConfigPanel.recursiveIsOpen() && executorService.getActiveCount() < 2){
                        //获取一个未访问URL列表
                        UnVisitedUrlsModel unVisitedUrlsModel =  AnalyseResultTable.fetchOneUnVisitedUrls( );
                        if (unVisitedUrlsModel != null){
                            //获取URL
                            List<String> unvisitedUrls = unVisitedUrlsModel.getUnvisitedUrls();

                            //将这些URl标记为已访问 不然涉及的更新的问题很多
                            //RecordUrlTable.batchInsertOrUpdateAccessedUrls(unvisitedUrls, 299);

                            //获取这个MsgHash对应的请求体和响应体
                            String msgHash = unVisitedUrlsModel.getMsgHash();
                            ReqMsgDataModel reqMsgDataModel = ReqMsgDataTable.fetchMsgDataByMsgHash(msgHash);
                            //获取请求头
                            HelperPlus helperPlus = new HelperPlus(getHelpers());
                            List<String> rawHeaders = helperPlus.getHeaderList(true, reqMsgDataModel.getReqBytes());
                            //记录准备加入的请求
                            executorService.submit(new Runnable() {
                                @Override
                                public void run() {
                                    for (String reqUrl:unvisitedUrls){
                                        if (urlAutoRecordMap.get(reqUrl) <= 0){
                                            //记录已访问的URL
                                            urlAutoRecordMap.add(reqUrl); //防止循环扫描
                                            RecordUrlTable.insertOrUpdateAccessedUrl(reqUrl,299);

                                            stdout_println(LOG_INFO, String.format("[*] Auto Access URL: %s", reqUrl));

                                            try {
                                                //发起HTTP请求
                                                IHttpRequestResponse requestResponse = BurpHttpUtils.makeHttpRequestForGet(reqUrl, rawHeaders);
                                                if (requestResponse != null) {
                                                    executorService.submit(new Runnable() {
                                                        @Override
                                                        public void run() {
                                                            HttpMsgInfo msgInfo = new HttpMsgInfo(requestResponse);
                                                            //更新所有有响应的主动访问请求URL记录到数据库中
                                                            RecordUrlTable.insertOrUpdateAccessedUrl(msgInfo);

                                                            //保存网站相关的所有 PATH, 便于后续path反查的使用 当响应状态 In [200 | 403 | 405] 说明路径存在 方法不准确,暂时关闭
                                                            if(ConfigPanel.autoRecordPathIsOpen()
                                                                    && isEqualsOneKey(msgInfo.getRespStatusCode(), CONF_NEED_RECORD_STATUS, false)
                                                                    && !msgInfo.getUrlInfo().getPath().equals("/")){
                                                                RecordPathTable.insertOrUpdateRecordPath(msgInfo);
                                                                stdout_println(LOG_DEBUG, String.format("Record reqBaseUrl: %s", msgInfo.getUrlInfo().getNoFileUrl()));
                                                            }

                                                            //加入请求分析列表
                                                            if (msgInfo.getRespInfo().getRespLength()>0)
                                                                insertOrUpdateReqDataAndReqMsgData(msgInfo,"Auto");

                                                            //放到后面,确保已经记录数据,不然会被过滤掉
                                                            urlScanRecordMap.add(msgInfo.getMsgHash());
                                                        }
                                                    });
                                                }
                                                Thread.sleep(500);
                                            } catch (InterruptedException e) {
                                                stderr_println(LOG_ERROR, String.format("Thread.sleep Error: %s", e.getMessage()));
                                                e.printStackTrace();
                                            }
                                        }
                                    }
                                }});
                        }
                    }
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
            PathTreeModel pathTreeModel = PathTreeTable.fetchPathTreeByReqHostPort(reqHostPort);
            //如果 PATH TREE都没有添加过, pathTreeModel 就是空的
            if (pathTreeModel == null){
                //如果 PATH TREE 不应该是空的,因为任务二已经添加过了,
                stderr_println(LOG_ERROR, String.format("[!] 获取 HOST [id:%s host:%s url:%s findPath:%s] 对应的 PathTree 失败!!! 请检查数据库内容!!!",id, reqHostPort, reqUrl, findPathArray.size()));
                return;
            }

            Integer currBasicPathNum = pathTreeModel.getBasicPathNum();
            JSONObject currPathTree = pathTreeModel.getPathTree();
            // 基于根树和paths列表计算新的字典
            //当获取到Path数据,并且路径树不为空时 可以计算新的URL列表
            if (findPathArray != null && !findPathArray.isEmpty() && currPathTree != null
                    && !currPathTree.isEmpty() && !currPathTree.getJSONObject("ROOT").isEmpty()) {
                List<String> findUrlsList = new ArrayList<>();
                //遍历路径列表,开始进行查询
                String reqBaseUrl = new HttpUrlInfo(reqUrl).getNoParamUrl();

                for (Object findPath: findPathArray){
                    JSONArray nodePath = PathTreeUtils.findNodePathInTree(currPathTree, (String) findPath);
                    //查询到结果就组合成URL,加到查询结果中
                    if (nodePath != null && !nodePath.isEmpty()){
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
