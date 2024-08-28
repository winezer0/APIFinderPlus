package model;

import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;

public class RecordPathModel {
    private String reqHash;
    private String rootUrl;
    private String reqPathDir;
    private int respStatusCode;

    public RecordPathModel(String rootUrl, String reqPathDir, int respStatusCode) {
        this.rootUrl = rootUrl;
        this.reqPathDir = reqPathDir;
        this.respStatusCode = respStatusCode;
        this.reqHash = getCalcCRC32();
    }

    public RecordPathModel(HttpUrlInfo urlInfo, int respStatusCode) {
        this.rootUrl = urlInfo.getRootUrlUsual();
        this.reqPathDir = urlInfo.getPathToDir();
        this.respStatusCode = respStatusCode;
        this.reqHash = getCalcCRC32();
    }

    private String getCalcCRC32() {
        return calcCRC32(String.format("%s|%s|%s", this.rootUrl, this.reqPathDir, this.respStatusCode));
    }

    /**
     * 计算给定字符串的CRC32校验和，并以十六进制字符串形式返回。
     * @param string 要计算CRC32的字符串
     * @return 字符串的CRC32校验和的十六进制表示
     */
    private String calcCRC32(String string) {
        // 使用 UTF-8 编码将字符串转换为字节数组
        byte[] inputBytes = string.getBytes(StandardCharsets.UTF_8);
        // 初始化CRC32对象
        CRC32 crc32 = new CRC32();
        // 更新CRC值
        crc32.update(inputBytes, 0, inputBytes.length);
        // 将计算后的CRC32值转换为十六进制字符串并返回
        return Long.toHexString(crc32.getValue()).toLowerCase();
    }


    public String getReqPathDir() {
        return reqPathDir;
    }

    public int getRespStatusCode() {
        return respStatusCode;
    }

    public String getReqHash() {
        return reqHash;
    }

    public String getRootUrl() {
        return rootUrl;
    }
}
