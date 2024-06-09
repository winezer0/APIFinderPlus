package burp;

import dataModel.RecordUrlsTable;
import dataModel.MsgDataTable;
import dataModel.ReqDataTable;
import model.HttpMsgInfo;
import model.UrlRecord;

import java.io.PrintWriter;
import java.util.Arrays;
import java.util.concurrent.*;

import static burp.BurpExtender.*;
import static utils.HttpUtils.isContainElements;
import static utils.HttpUtils.isContainInElements;


public class IProxyScanner implements IProxyListener {
    private static PrintWriter stdout = BurpExtender.getStdout();
    private static PrintWriter stderr = BurpExtender.getStderr();
    private static IExtensionHelpers helpers = BurpExtender.getHelpers();

    private static final int MaxRespBodyLen = 200000; //最大支持处理的响应
    private static UrlRecord urlScannedRecord = new UrlRecord(); //记录已加入扫描列表的URL Hash
    private static UrlRecord urlPathDirRecord = new UrlRecord(); //记录已加入待分析记录的URL Path Dir

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
        stdout.println("[+] run executorService maxPoolSize: " + coreCount + " ~ " + maxPoolSize + ", monitorExecutorServiceNumberOfIntervals: " + monitorExecutorServiceNumberOfIntervals);

        monitorExecutor = Executors.newSingleThreadScheduledExecutor();
    }

    public void processProxyMessage(boolean messageIsRequest, final IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!messageIsRequest) {
            HttpMsgInfo msgInfo = new HttpMsgInfo(iInterceptedProxyMessage);
            //判断是否是正常的响应 //返回结果为空则退出
            if (msgInfo.getRespBytes() == null || msgInfo.getRespBytes().length == 0) {
                stdout.println("[-] 没有响应内容 跳过插件处理：" + msgInfo.getReqUrl());
                return;
            }

            //看URL识别是否报错
            if (msgInfo.getReqBaseUrl() == null ||msgInfo.getReqBaseUrl().equals("-")){
                stdout.println("[-] URL转化失败 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            //匹配黑名单域名
            if(isContainElements(msgInfo.getReqHost(), UN_CHECKED_URL_DOMAIN, false)){
                stdout.println("[-] 匹配黑名单域名 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            //保存网站相关的所有 PATH, 便于后续path反查的使用
            //当响应状态 In [200 | 403 | 405] 说明路径存在 此时可以将URL存储已存在字典
            //String allowStatus = "200|403|405";
            if(urlPathDirRecord.get(msgInfo.getReqBasePath()) <= 0 &&
                    isContainInElements(msgInfo.getRespStatus(), RECORD_STATUS_CODE, true)){
                //stdout.println("[*] URL响应正常, 加入 URL PATH存储表");
                RecordUrlsTable.insertOrUpdateSuccessUrl(msgInfo);
                urlPathDirRecord.add(msgInfo.getReqBasePath());
            }

            // 排除黑名单后缀
            if(isContainInElements(msgInfo.getReqPathExt(), UN_CHECKED_URL_EXT, false)
                    || msgInfo.getReqUrl().contains("favicon.")){
                stdout.println("[-] 匹配黑名单后缀 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            //排除黑名单路径 这些JS文件是通用的、无价值的、
            //String blackPaths = "jquery.js|xxx.js";
            if(isContainElements(msgInfo.getReqPath(), UN_CHECKED_URL_PATH, false)){
                stdout.println("[-] 匹配黑名单路径 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            // 看status是否为30开头
            if (msgInfo.getRespStatus().startsWith("3")){
                stdout.println("[-] URL的响应包状态码3XX 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            if (msgInfo.getRespStatus().equals("404")){
                stdout.println("[-] URL的响应包状态码404 跳过url识别：" + msgInfo.getReqUrl());
                return;
            }

            //判断URL是否已经扫描过
            if (urlScannedRecord.get(msgInfo.getMsgHash()) > 0) {
                stdout.println(String.format("[-] 已添加过URL: %s -> %s", msgInfo.getReqUrl(), msgInfo.getMsgHash()));
                return;
            }

            //防止响应体过大
            byte[] responseBytes = msgInfo.getRespBytes().length > MaxRespBodyLen ? Arrays.copyOf(msgInfo.getRespBytes(), MaxRespBodyLen) : msgInfo.getRespBytes();
            msgInfo.setRespBytes(responseBytes);

            //记录准备加入的请求
            urlScannedRecord.add(msgInfo.getMsgHash());

            //存储请求体|响应体数据
            int msgDataIndex = MsgDataTable.insertOrUpdateMsgData(msgInfo);
            if (msgDataIndex <= 0){
                stderr.println("[!] error in insertOrUpdateMsgData: " + msgInfo.getReqUrl());
                return;
            } else {
                // 存储到URL表
                int msgId = iInterceptedProxyMessage.getMessageReference();
                int insertOrUpdateOriginalDataIndex = ReqDataTable.insertOrUpdateReqData(msgInfo, msgId, msgDataIndex);
                if (insertOrUpdateOriginalDataIndex <= 0){
                    stderr.println("[!] error in insertOrUpdateReqData: " + msgInfo.getReqUrl());
                    return;
                }else {
                    stdout.println(String.format("[+] Add To db: %s -> msgHash: %s", msgInfo.getReqUrl(), msgInfo.getMsgHash()));
                }
            }
        }
//            totalScanCount += 1;
//            ConfigPanel.lbRequestCount.setText(Integer.toString(totalScanCount));
//

//
//            // 网页提取URL并进行指纹识别
//            executorService.submit(new Runnable() {
//                @Override
//                public void run() {
//                    DatabaseService dbs = BurpExtender.getDataBaseService();
//                    // 存储请求体|响应体数据
//                    int msgIndex =  dbs.insertOrUpdateReqResData(uniqueCode, url, msgInfo.getRequest(), msgInfo.getResponse());
//                    if (msgIndex == -1){
//                        stderr.println("[!] error in insertOrUpdateReqResData: " + url);
//                        return;
//                    }
//                    // 存储到URL表
//                    int msgId = iInterceptedProxyMessage.getMessageReference();
//                    int insertOrUpdateOriginalDataIndex = dbs.insertOrUpdateOriginData(uniqueCode, url, msgId, statusCode, reqMethod, msgIndex, msgInfo.getHttpService());
//                    if (insertOrUpdateOriginalDataIndex == -1){
//                        stderr.println("[!] error in insertOrUpdateOriginData: " + url);
//                        return;
//                    }
//                }
//            });
//

//        }

    }

}
