package database;

import model.AccessedUrlInfo;
import model.HttpMsgInfo;
import model.HttpUrlInfo;
import utils.CastUtils;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static utils.BurpPrintUtils.*;

public class RecordUrlTable {
    //数据表名称
    public static String tableName = "RECORD_URL";
    public static String urlHashName = "url_hash";

    //创建用于存储所有 访问成功的 URL的数据库 record_urls
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS  "+ tableName +"  (\n"
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,\n"  //自增的id
            + "url_hash TEXT UNIQUE,\n"
            + "root_url TEXT NOT NULL,\n"
            + "req_url TEXT NOT NULL,\n"  //记录访问过的URL
            + "resp_status_code INTEGER\n" //记录访问过的URL状态
            + ");";


    //插入访问的URl
    public static synchronized int insertOrUpdateAccessedUrl(String reqUrl,String rootUrl, int respStatusCode, String urlHash) {
        int generatedId = -1;
        String upsertSql = "INSERT INTO "+ tableName +
                " (req_url, root_url, resp_status_code, url_hash)" +
                " VALUES (?,?, ?, ?)" +
                " ON CONFLICT(url_hash) DO UPDATE SET resp_status_code = EXCLUDED.resp_status_code;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(upsertSql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, reqUrl);
            stmt.setString(2, rootUrl);
            stmt.setInt(3, respStatusCode);
            stmt.setString(4, urlHash);

            stmt.executeUpdate();

            try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    generatedId = generatedKeys.getInt(1);
                }
            }
        } catch (SQLException e) {
            System.err.println(String.format("Error insert Or Update Accessed Url On table [%s] -> Error:[%s]", tableName, e.getMessage()));
        }

        return generatedId;
    }

    //插入访问的URl 复用
    public static synchronized int insertOrUpdateAccessedUrl(HttpMsgInfo msgInfo) {
        return insertOrUpdateAccessedUrl(
                msgInfo.getUrlInfo().getRawUrlUsual(),
                msgInfo.getUrlInfo().getHostPort(),
                msgInfo.getRespStatusCode(),
                CastUtils.calcCRC32(msgInfo.getUrlInfo().getRawUrlUsual())
        );
    }

    //插入访问的URl 复用
    public static synchronized int insertOrUpdateAccessedUrl(String reqUrl, int respStatusCode) {
        return insertOrUpdateAccessedUrl(reqUrl, new HttpUrlInfo(reqUrl).getHostPort(), respStatusCode, CastUtils.calcCRC32(reqUrl));
    }

    //实现批量插入访问信息
    public static synchronized int[] batchInsertOrUpdateAccessedUrls(List<AccessedUrlInfo> accessedUrlInfos) {
        int[] generatedIds = null;

        String upsertSql = "INSERT INTO "+ tableName +
                " (req_url, root_url, resp_status_code, url_hash)" +
                " VALUES (?, ?, ?, ?)" +
                " ON CONFLICT(url_hash) DO UPDATE SET resp_status_code = EXCLUDED.resp_status_code;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(upsertSql, Statement.RETURN_GENERATED_KEYS)) {
            // 添加到批处理队列
            conn.setAutoCommit(false); // 开启事务
            for (AccessedUrlInfo accessedUrlInfo : accessedUrlInfos) {
                stmt.setString(1, accessedUrlInfo.getReqUrl());
                stmt.setString(2, accessedUrlInfo.getRootUrl());
                stmt.setInt(3, accessedUrlInfo.getRespStatusCode());
                stmt.setString(4, accessedUrlInfo.getUrlHash());
                stmt.addBatch();
            }
            // 执行批处理
            generatedIds = stmt.executeBatch();
            conn.commit(); // 提交事务

        } catch (Exception e) {
            System.err.println(String.format("Error [%s] batch insert Or Update Accessed Urls: %s", tableName, e.getMessage()));
        }

        return generatedIds;
    }


    //实现批量插入访问信息 复用
    public static synchronized int[] batchInsertOrUpdateAccessedUrls(List<String> accessedUrls, int respStatusCode){
        List<AccessedUrlInfo> accessedUrlInfos = new ArrayList<>();
        for (String reqUrl : accessedUrls){
            AccessedUrlInfo accessedUrlInfo = new AccessedUrlInfo(reqUrl, new HttpUrlInfo(reqUrl).getRootUrlUsual(),respStatusCode);
            accessedUrlInfos.add(accessedUrlInfo);
        }
        return batchInsertOrUpdateAccessedUrls(accessedUrlInfos);
    }
}
