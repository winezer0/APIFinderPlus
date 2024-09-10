package database;

import model.AnalyseUrlResultModel;
import model.BasicUrlTableTabDataModel;
import model.FindPathModel;
import model.HttpMsgInfo;
import utils.CastUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpPrintUtils.*;

public class AnalyseUrlResultTable {
    //数据表名称
    public static String tableName = "ANALYSE_URL_RESULT";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL  = "CREATE TABLE IF NOT EXISTS "+ tableName +" (\n"
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + "msg_hash TEXT UNIQUE,\n"  //请求Hash信息
            + "req_url TEXT NOT NULL,\n"  //请求URL
            + "root_url TEXT NOT NULL,\n"  //请求HOST PORT

            + "find_url TEXT DEFAULT '',\n"    //分析出来的URL信息 (Json格式)
            + "find_url_num INTEGER DEFAULT -1,\n"     //发现URL的数量

            + "find_path TEXT DEFAULT '',\n"   //分析出来的URI信息 还需要补充路径 (Json格式)
            + "find_path_num INTEGER DEFAULT -1,\n"    //发现PATH的数量

            + "find_info TEXT DEFAULT '',\n"   //分析出来的敏感信息(Json格式)
            + "find_info_num INTEGER DEFAULT -1,\n"    //发现INFO的数量
            + "has_important INTEGER DEFAULT 0,\n"    //是否存在重要信息

            + "find_api TEXT DEFAULT '',\n"        //基于分析的不完整URI信息 直接拼接 出来的URL (Json格式)
            + "find_api_num INTEGER DEFAULT -1,\n"     //发现API的数量

            + "basic_path_num INTEGER DEFAULT -1,\n"     //是基于多少个路径算出来的结果?

            + "run_status TEXT NOT NULL DEFAULT 'RUN_STATUS'".replace("RUN_STATUS", Constants.ANALYSE_WAIT)

            + ");";

    /**
     * 插入第一次分析完毕的 URL和PATH结果, 此时不包含动态生成的URL
     * @param msgInfo
     * @param analyseInfo
     * @return
     */
    public static synchronized int insertOrUpdateBasicAnalyseResult(HttpMsgInfo msgInfo, AnalyseUrlResultModel analyseInfo){
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String selectSql = "SELECT id FROM "+ tableName +" WHERE msg_hash = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt1 = conn.prepareStatement(selectSql)) {
            // 检查记录是否存在
            stmt1.setString(1, msgInfo.getMsgHash());
            ResultSet rs = stmt1.executeQuery();
            if (rs.next()) {
                // 记录存在，执行更新
                stdout_println(LOG_INFO, String.format("[*] Update [%s] %s -> %s", tableName, msgInfo.getUrlInfo().getRawUrlUsual(), msgInfo.getMsgHash()));

                String updateSql = "UPDATE " + tableName + " SET "
                        + "req_url = ?, root_url = ?, find_url = ?, find_url_num = ?, "
                        + "find_path = ?, find_path_num = ?, find_info = ?, find_info_num = ?, "
                        + "find_api = ?, find_api_num = ?, run_status = ?, has_important = ? "
                        + "WHERE msg_hash = ?;"; // 注意最后的where子句

                try (PreparedStatement stmtUpdate = conn.prepareStatement(updateSql)) {
                    stmtUpdate.setString(1, msgInfo.getUrlInfo().getRawUrlUsual());
                    stmtUpdate.setString(2, msgInfo.getUrlInfo().getRootUrlUsual());

                    stmtUpdate.setString(3, CastUtils.toJsonString(analyseInfo.getUrlList()));
                    stmtUpdate.setInt(4, analyseInfo.getUrlList().size());

                    stmtUpdate.setString(5, CastUtils.toJsonString(analyseInfo.getPathList()));
                    stmtUpdate.setInt(6, analyseInfo.getPathList().size());

                    stmtUpdate.setString(7, CastUtils.toJsonString(analyseInfo.getInfoArray()));
                    stmtUpdate.setInt(8, analyseInfo.getInfoArray().size());

                    stmtUpdate.setString(9, CastUtils.toJsonString(analyseInfo.getApiList()));
                    stmtUpdate.setInt(10, analyseInfo.getApiList().size());

                    stmtUpdate.setString(11, Constants.ANALYSE_WAIT);
                    stmtUpdate.setBoolean(12, analyseInfo.getHasImportant());

                    stmtUpdate.setString(13, msgInfo.getMsgHash()); // 设置where子句中的msg_hash

                    stmtUpdate.executeUpdate();

                    generatedId = rs.getInt("id"); // 使用已存在的ID
                }

            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO "+ tableName +"" +
                        " (msg_hash, req_url, root_url, find_url, find_url_num, find_path, find_path_num," +
                        " find_info, find_info_num, find_api, find_api_num, run_status, has_important)" +
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

                try (PreparedStatement stmt2 = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    stmt2.setString(1, msgInfo.getMsgHash());
                    stmt2.setString(2, msgInfo.getUrlInfo().getRawUrlUsual());
                    stmt2.setString(3, msgInfo.getUrlInfo().getRootUrlUsual());

                    stmt2.setString(4, CastUtils.toJsonString(analyseInfo.getUrlList()));
                    stmt2.setInt(5, analyseInfo.getUrlList().size());

                    stmt2.setString(6, CastUtils.toJsonString(analyseInfo.getPathList()));
                    stmt2.setInt(7, analyseInfo.getPathList().size());

                    stmt2.setString(8, CastUtils.toJsonString(analyseInfo.getInfoArray()));
                    stmt2.setInt(9, analyseInfo.getInfoArray().size());

                    stmt2.setString(10, CastUtils.toJsonString(analyseInfo.getApiList()));
                    stmt2.setInt(11, analyseInfo.getApiList().size());

                    //设置初始的响应状态为 等待处理
                    stmt2.setString(12, Constants.ANALYSE_WAIT);

                    stmt2.setBoolean(13, analyseInfo.getHasImportant());

                    stmt2.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = stmt2.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            generatedId = generatedKeys.getInt(1); // 获取生成的ID
                        }
                    }
                }
            }
        } catch (Exception e) {
            stderr_println(String.format("[-] Error inserting or updating table [%s] -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }

        return generatedId; //返回ID值，无论是更新还是插入
    }

    /**
     * 获取 指定 msgHashList 对应的 所有 分析结果 数据
     * @return
     */
    public static synchronized List<AnalyseUrlResultModel> fetchUrlResultByMsgHashList(List<String> msgHashList){
        List<AnalyseUrlResultModel> AnalyseUrlResultModels = new ArrayList<>();

        if (msgHashList.isEmpty()) return AnalyseUrlResultModels;

        String selectSQL = ("SELECT * FROM " + tableName + " WHERE msg_hash IN $buildInParamList$;")
                .replace("$buildInParamList$", DBService.buildInParamList(msgHashList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            for (int i = 0; i < msgHashList.size(); i++) {
                stmt.setString(i + 1, msgHashList.get(i));
            }

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                AnalyseUrlResultModel tabDataModel = new AnalyseUrlResultModel(
                        rs.getString("req_url"),
                        rs.getString("find_info"),
                        rs.getString("find_url"),
                        rs.getString("find_path"),
                        rs.getString("find_api"),
                        rs.getBoolean("has_important")
                );
                AnalyseUrlResultModels.add(tabDataModel);
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] Result Data By MsgHash List: %s",tableName, e.getMessage()));
        }
        return AnalyseUrlResultModels;
    }

    /**
     * 获取 指定 msgHash 对应的 所有 分析结果 数据, 用于填充 UI 表的下方 tab 数据
     */
    public static synchronized BasicUrlTableTabDataModel fetchUrlResultByMsgHash(String msgHash){
        BasicUrlTableTabDataModel tabDataModel = null;

        String selectSQL = "SELECT * FROM "+ tableName +" WHERE msg_hash = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setString(1, msgHash);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    tabDataModel = new BasicUrlTableTabDataModel(
                            rs.getString("msg_hash"),
                            rs.getString("find_url"),
                            rs.getString("find_path"),
                            rs.getString("find_info"),
                            rs.getString("find_api")
                    );
                }
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error Select Analyse Result Data By MsgHash: %s", e.getMessage()));
        }
        return tabDataModel;
    }

    /**
     * 获取多条 存在 Path 并且没有 动态计算过的 path数据
     */
    public static synchronized List<FindPathModel> fetchPathDataByMsgHashList(List<String> msgHashList){
        List<FindPathModel> findPathModelList = new ArrayList<>();

        if (msgHashList.isEmpty()) return findPathModelList;

        String selectSQL = "SELECT * FROM " + tableName + " WHERE msg_hash IN $buildInParamList$;"
                .replace("$buildInParamList$", DBService.buildInParamList(msgHashList.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            for (int i = 0; i < msgHashList.size(); i++) {
                stmt.setString(i + 1, msgHashList.get(i));
            }
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                FindPathModel findPathModel =  new FindPathModel(
                        rs.getInt("id"),
                        rs.getString("root_url"),
                        rs.getString("find_path")
                );

                findPathModelList.add(findPathModel);
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] Path Data By MsgHash List: %s", tableName, e.getMessage()));
        }
        return findPathModelList ;
    }

}
