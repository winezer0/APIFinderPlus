package database;

import com.alibaba.fastjson2.JSONArray;
import model.AnalyseHostResultModel;
import utils.CastUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;

import static utils.BurpPrintUtils.stderr_println;

public class AnalyseHostResultTable {
    //数据表名称
    public static String tableName = "ANALYSE_HOST_RESULT";

    //创建用于存储 需要处理的URL的原始请求响应
    static String creatTableSQL  = "CREATE TABLE IF NOT EXISTS "+ tableName +" (\n"
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + "root_url TEXT NOT NULL,\n"  //请求URL

            + "find_info TEXT DEFAULT '',\n"   //分析出来的敏感信息(Json格式)
            + "find_info_num INTEGER DEFAULT -1,\n"    //发现INFO的数量
            + "has_important INTEGER DEFAULT 0,\n"    //是否存在重要信息

            + "find_url TEXT DEFAULT '',\n"    //分析出来的URL信息 (Json格式)
            + "find_url_num INTEGER DEFAULT -1,\n"     //发现URL的数量

            + "find_path TEXT DEFAULT '',\n"   //分析出来的URI信息 还需要补充路径 (Json格式)
            + "find_path_num INTEGER DEFAULT -1,\n"    //发现PATH的数量

            + "find_api TEXT DEFAULT '',\n"        //基于分析的不完整URI信息 直接拼接 出来的URL (Json格式)
            + "find_api_num INTEGER DEFAULT -1,\n"     //发现API的数量

            + "path_to_url TEXT DEFAULT '',\n"      //基于分析的不完整URI信息 智能计算 出来的URL (Json格式)
            + "path_to_url_num INTEGER DEFAULT -1,\n"     //发现API的数量

            + "unvisited_url TEXT DEFAULT '',\n"      //合并所有URL 并去除已经访问过的URL (Json格式)
            + "unvisited_url_num INTEGER DEFAULT -1,\n"   //合并所有URL 并去除已经访问过的URL的数量

            + "basic_path_num INTEGER DEFAULT -1,\n"     //是基于多少个路径算出来的结果?

            + "run_status TEXT NOT NULL DEFAULT 'ANALYSE_WAIT'"  //预留 不需要的话后面可以删除
            .replace("ANALYSE_WAIT", Constants.ANALYSE_WAIT)

            + ");";



    /**
     * 为每个HOST插入分析结果, 此时不包含动态生成的URL
     */
    public static synchronized int insertOrUpdateAnalyseHostResult(AnalyseHostResultModel analyseHostResultModel){
        String rootUrl = analyseHostResultModel.getRootUrl();
        JSONArray infoArray = analyseHostResultModel.getInfoArray();
        List<String> urlList = analyseHostResultModel.getUrlList();
        List<String> pathList = analyseHostResultModel.getPathList();
        List<String> apiList = analyseHostResultModel.getApiList();
        Boolean hasImportant = analyseHostResultModel.getHasImportant();
        List<String> unvisitedUrlList = analyseHostResultModel.getUnvisitedUrlList();

        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值

        String selectSql = "SELECT * FROM "+ tableName +" WHERE root_url = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt1 = conn.prepareStatement(selectSql)) {
            // 检查记录是否存在
            stmt1.setString(1, rootUrl);
            ResultSet rs = stmt1.executeQuery();
            if (!rs.next()) {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO "+ tableName + " " +
                        "(root_url, find_info, find_info_num, has_important, " +
                        "find_url, find_url_num, find_path, find_path_num, find_api, find_api_num, " +
                        "unvisited_url, unvisited_url_num, run_status) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

                try (PreparedStatement stmt2 = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    stmt2.setString(1, rootUrl);

                    stmt2.setString(2, CastUtils.toJsonString(infoArray));
                    stmt2.setInt(3, infoArray.size());
                    stmt2.setBoolean(4, hasImportant);

                    stmt2.setString(5, CastUtils.toJsonString(urlList));
                    stmt2.setInt(6, urlList.size());

                    stmt2.setString(7, CastUtils.toJsonString(pathList));
                    stmt2.setInt(8, pathList.size());

                    stmt2.setString(9, CastUtils.toJsonString(apiList));
                    stmt2.setInt(10, apiList.size());

                    stmt2.setString(11, CastUtils.toJsonString(unvisitedUrlList));
                    stmt2.setInt(12,unvisitedUrlList.size());

                    //设置初始的响应状态为 等待处理
                    stmt2.setString(13, Constants.ANALYSE_WAIT);

                    stmt2.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = stmt2.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            generatedId = generatedKeys.getInt(1); // 获取生成的ID
                        }
                    }
                }

                return 0;
            } else {
                int id = rs.getInt("id");
                JSONArray oldInfoArray = CastUtils.toJsonArray(rs.getString("find_info"));
                Boolean oldHasImportant = rs.getBoolean("has_important");
                List<String> oldUrlList = CastUtils.toStringList(rs.getString("find_url"));
                List<String> oldPathList = CastUtils.toStringList(rs.getString("find_path"));
                List<String> oldApiList = CastUtils.toStringList(rs.getString("find_api"));
                List<String> oldUnvisitedUrlList = CastUtils.toStringList(rs.getString("unvisited_url"));

                // 记录存在 合并旧的数据 更新记录
                String updateSql = "UPDATE " + tableName + " SET " +
                        "find_info = ?, find_info_num = ?, has_important = ?, " +
                        "find_url = ?, find_url_num = ?, find_path = ?, find_path_num = ?, find_api = ?, find_api_num = ?, " +
                        "unvisited_url = ?, unvisited_url_num = ?, run_status = ? " +
                        "WHERE root_url = ?";

                try (PreparedStatement stmt2 = conn.prepareStatement(updateSql)) {
                    //find_info
                    JSONArray newInfoArray = CastUtils.listAddList(infoArray, oldInfoArray);
                    stmt2.setString(1, CastUtils.toJsonString(newInfoArray));
                    stmt2.setInt(2, newInfoArray.size());

                    //has_important
                    stmt2.setBoolean(3, hasImportant||oldHasImportant);

                    List<String> newUrlList = CastUtils.listAddList(urlList, oldUrlList);
                    stmt2.setString(4, CastUtils.toJsonString(newUrlList));
                    stmt2.setInt(5, newUrlList.size());

                    List<String> newPathList = CastUtils.listAddList(pathList, oldPathList);
                    stmt2.setString(6, CastUtils.toJsonString(newPathList));
                    stmt2.setInt(7, newPathList.size());

                    List<String> newApiList = CastUtils.listAddList(apiList, oldApiList);
                    stmt2.setString(8, CastUtils.toJsonString(newApiList));
                    stmt2.setInt(9, newApiList.size());

                    List<String> newUnvisitedUrlList = CastUtils.listAddList(unvisitedUrlList, oldUnvisitedUrlList);
                    stmt2.setString(10, CastUtils.toJsonString(newUnvisitedUrlList));
                    stmt2.setInt(11, newUnvisitedUrlList.size());

                    // 设置响应状态为处理中
                    stmt2.setString(12, Constants.ANALYSE_ING);

                    stmt2.setString(13, rootUrl);

                    stmt2.executeUpdate();

                    // 如果需要获取更新记录的ID，可以查询主键
                    generatedId = id; // 假设id是主键且名为"id"
                }
            }
        } catch (Exception e) {
            stderr_println(String.format("[-] Error inserting or updating table [%s] -> Error:[%s]", tableName, e.getMessage()));
            e.printStackTrace();
        }

        return generatedId; //返回ID值，无论是更新还是插入
    }

}
