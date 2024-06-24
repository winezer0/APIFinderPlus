package burp;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import dataModel.*;
import model.HttpMsgInfo;
import model.RecordHashMap;
import model.InfoAnalyse;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.*;

import static burp.BurpExtender.*;
import static dataModel.InfoAnalyseTable.fetchOneAnalysePathData;
import static dataModel.PathRecordTable.fetchUnhandledRecordUrlId;
import static dataModel.PathTreeTable.fetchOnePathTree;
import static dataModel.PathTreeTable.insertOrUpdatePathTree;
import static dataModel.PathRecordTable.fetchUnhandledRecordUrls;
import static model.InfoAnalyse.analyseInfoIsNotEmpty;
import static utils.PathTreeUtils.genPathsTree;
import static utils.BurpPrintUtils.*;
import static utils.ElementUtils.isContainOneKey;
import static utils.ElementUtils.isEqualsOneKey;


public class IProxyScanner implements IProxyListener {
    private static final int MaxRespBodyLen = 200000; //最大支持处理的响应
    private static RecordHashMap urlScanRecordMap = new RecordHashMap(); //记录已加入扫描列表的URL Hash
    private static RecordHashMap urlPathRecordMap = new RecordHashMap(); //记录已加入待分析记录的URL Path Dir

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
//            totalScanCount += 1;
//            ConfigPanel.lbRequestCount.setText(Integer.toString(totalScanCount));

            HttpMsgInfo msgInfo = new HttpMsgInfo(iInterceptedProxyMessage);
            //判断是否是正常的响应 //返回结果为空则退出
            if (msgInfo.getRespBytes() == null || msgInfo.getRespBytes().length == 0) {
                stdout_println(LOG_DEBUG,"[-] 没有响应内容 跳过插件处理：" + msgInfo.getReqUrl());
                return;
            }

            //看URL识别是否报错
            if (msgInfo.getReqBaseUrl() == null ||msgInfo.getReqBaseUrl().equals("-")){
                stdout_println(LOG_ERROR,"[-] URL转化失败 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            //匹配黑名单域名
            if(isContainOneKey(msgInfo.getReqHost(), CONF_BLACK_URL_HOSTS, false)){
                stdout_println(LOG_DEBUG,"[-] 匹配黑名单域名 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            //保存网站相关的所有 PATH, 便于后续path反查的使用
            //当响应状态 In [200 | 403 | 405] 说明路径存在 此时可以将URL存储已存在字典
            if(urlPathRecordMap.get(msgInfo.getReqBasePath()) <= 0
                    && isEqualsOneKey(msgInfo.getRespStatusCode(), CONF_NEED_RECORD_STATUS, true)
                    && msgInfo.getReqPath().trim() != "/"
            ){
                urlPathRecordMap.add(msgInfo.getReqBasePath());
                stdout_println(LOG_INFO, String.format("[+] Record ReqBasePath: %s -> %s", msgInfo.getReqBasePath(), msgInfo.getRespStatusCode()));
                executorService.submit(new Runnable() {
                    @Override
                    public void run() {
                        PathRecordTable.insertOrUpdateSuccessUrl(msgInfo);
                    }
                });
            }

            // 排除黑名单后缀
            if(isEqualsOneKey(msgInfo.getReqPathExt(), CONF_BLACK_URL_EXT, false)){
                stdout_println(LOG_DEBUG, "[-] 匹配黑名单后缀 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            //排除黑名单路径 这些JS文件是通用的、无价值的、
            //String blackPaths = "jquery.js|xxx.js";
            if(isContainOneKey(msgInfo.getReqPath(), CONF_BLACK_URL_PATH, false)){
                stdout_println(LOG_DEBUG, "[-] 匹配黑名单路径 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            // 看status是否为30开头
            if (msgInfo.getRespStatusCode().startsWith("3")){
                stdout_println(LOG_DEBUG,"[-] URL的响应包状态码3XX 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            if (msgInfo.getRespStatusCode().equals("404")){
                stdout_println(LOG_DEBUG, "[-] URL的响应包状态码404 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            //判断URL是否已经扫描过
            if (urlScanRecordMap.get(msgInfo.getMsgHash()) > 0) {
                stdout_println(LOG_DEBUG, String.format("[-] 已添加过URL: %s -> %s", msgInfo.getReqUrl(), msgInfo.getMsgHash()));
                return;
            }

            //记录准备加入的请求
            urlScanRecordMap.add(msgInfo.getMsgHash());
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    //防止响应体过大
                    byte[] respBytes = msgInfo.getRespBytes().length > MaxRespBodyLen ? Arrays.copyOf(msgInfo.getRespBytes(), MaxRespBodyLen) : msgInfo.getRespBytes();
                    msgInfo.setRespBytes(respBytes);
                    //加入请求列表
                    int msgId = iInterceptedProxyMessage.getMessageReference();
                    storeReqData(msgInfo, msgId, "ProxyMessage");
                }
            });
        }
    }

    /**
     * 合并添加请求数据和请求信息为一个函数
     * @param msgInfo
     * @param msgId
     */
    private void storeReqData(HttpMsgInfo msgInfo, int msgId, String reqSource) {
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
                    Integer needAnalyseDataIndex = ReqDataTable.fetchUnhandledReqDataId(true);
                    if (needAnalyseDataIndex > 0){
                        // 1 获取 msgDataIndex 对应的数据
                        Map<String, Object> needAnalyseData = ReqMsgDataTable.selectMsgDataById(needAnalyseDataIndex);
                        String requestUrl = (String) needAnalyseData.get(ReqMsgDataTable.req_url);
                        byte[] requestBytes = (byte[]) needAnalyseData.get(ReqMsgDataTable.req_bytes);
                        byte[] responseBytes = (byte[]) needAnalyseData.get(ReqMsgDataTable.resp_bytes);
                        String msgInfoHash = (String) needAnalyseData.get(ReqMsgDataTable.msg_hash);

                        //2.2 将请求响应数据整理出新的 MsgInfo 数据 并 分析
                        HttpMsgInfo msgInfo =  new HttpMsgInfo(requestUrl, requestBytes, responseBytes,msgInfoHash);

                        //2.3 进行数据分析
                        stdout_println(LOG_INFO, String.format("[+] 数据分析开始: %s -> msgHash: %s", msgInfo.getReqUrl(), msgInfo.getMsgHash()));
                        JSONObject analyseResult = InfoAnalyse.analysisMsgInfo(msgInfo);

                        //2.3 将分析结果写入数据库
                        if(analyseInfoIsNotEmpty(analyseResult)){
                            int analyseDataIndex = InfoAnalyseTable.insertAnalyseData(msgInfo, analyseResult);
                            if (analyseDataIndex > 0)
                                stdout_println(LOG_INFO, String.format("[+] 数据分析完成: %s -> msgHash: %s", msgInfo.getReqUrl(), msgInfo.getMsgHash()));
                        }
                    }

                    //判断是否还有需要分析的数据,如果没有的话，就可以考虑计算结果
                    int unhandledReqDataId = ReqDataTable.fetchUnhandledReqDataId(false);
                    if (unhandledReqDataId <= 0){
                        //1、更新|生成路径树
                        //"SELECT req_host, GROUP_CONCAT(req_path_dir, '<-->') AS req_path_dirs FROM record_paths GROUP BY req_host"
                        JSONArray recordUrls = fetchUnhandledRecordUrls();
                        if (recordUrls.size() > 0){
                            //计算所有需要更新的Tree
                            for (Object record : recordUrls) {
                                JSONObject treeObj = genPathsTree((JSONObject) record);
                                if (treeObj != null && !treeObj.isEmpty()){
                                    int pathTreeIndex = insertOrUpdatePathTree(treeObj);
                                    if (pathTreeIndex > 0)
                                        stdout_println(LOG_INFO, String.format("[+] Path Tree 更新成功: %s",treeObj.toJSONString()));
                                }
                            }
                        }



                    //todo: 提取的PATH需要进一步过滤处理
                    // 考虑增加后缀过滤功能 static/image/k8-2.png
                    // 考虑增加已有URL过滤 /bbs/login
                    // 考虑增加 参数处理 plugin.php?id=qidou_assign


                    //todo: 增加自动递归查询功能
                    }


                    //判断是否有树需要更新,没有的话就可以计算了
                    int unhandledRecordUrlId = fetchUnhandledRecordUrlId();
                    if (unhandledRecordUrlId <= 0) {
                        //todo 从数据库查询一条 path数据, 获取 id|msg_hash、PATHS列表
                        Map<String, Object> analysePathData = fetchOneAnalysePathData();
                        if (analysePathData != null) {
                            int dataId = (int) analysePathData.get(Constants.DATA_ID); //后面用来更新到数据表

                            String reqHostPort = (String) analysePathData.get(Constants.REQ_HOST_PORT);
                            String findPath = (String) analysePathData.get(Constants.FIND_PATH);
                            System.out.println(String.format("获取到域名%s对应的数据%s", reqHostPort, findPath));

                            // 5、从数据库中查询树信息表
                            String pathTree = fetchOnePathTree(reqHostPort);
                            System.out.println(String.format("获取到域名%s对应的数据%s", reqHostPort, pathTree));

                            //todo 基于根树和paths列表计算新的字典
                            //基于 根树 和 pathList 计算 URLs, 如果计算过的，先判断根数是否更新过
                        }
                    }
                }catch (Exception e) {
                    stderr_println(String.format("[!] scheduleAtFixedRate error: %s", e.getMessage()));
                    e.printStackTrace();
                }
            });
        }, 0, monitorExecutorServiceNumberOfIntervals, TimeUnit.SECONDS);
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
