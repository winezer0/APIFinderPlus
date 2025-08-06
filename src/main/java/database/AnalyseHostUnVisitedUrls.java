package database;

import com.alibaba.fastjson2.JSONArray;
import model.UnVisitedUrlsModel;
import utils.CastUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import static utils.BurpPrintUtils.LOG_ERROR;
import static utils.BurpPrintUtils.stderr_println;

public class AnalyseHostUnVisitedUrls {

    /**
     * 实现 基于 rootUrls 列表 删除 unvisitedUrls
     */
    public static synchronized int clearUnVisitedUrlsByRootUrls(List<String> rootUrls) {
        int totalRowsAffected = 0;
        if (rootUrls.isEmpty()) return totalRowsAffected;

        // 构建SQL语句
        String updateSQL = ("UPDATE "+ AnalyseHostResultTable.tableName + " SET unvisited_url = ?, unvisited_url_num = 0" +
                " WHERE root_url IN $buildInParamList$;")
                .replace("$buildInParamList$", SqlUtils.buildInParamList(rootUrls.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(updateSQL)) {
            // 设置第一个参数为JSON数组的toJSONString()
            stmt.setString(1, new JSONArray().toJSONString());

            // 循环设置参数 // 开始于第二个参数位置，第一个参数已被设置
            for (int i = 0; i < rootUrls.size(); i++) {
                stmt.setString(i + 2, rootUrls.get(i));
            }
            // 执行更新操作并获取受影响行数
            totalRowsAffected = stmt.executeUpdate();

        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error clearing unvisited URLs by RootUrls: %s", e.getMessage()));
        }
        return totalRowsAffected;
    }

    /**
     * 获取 所有未访问URl (unvisited_url_num > 0)
     * @return
     */
    public static synchronized List<UnVisitedUrlsModel> fetchAllUnVisitedUrlsWithLimit(Integer limit){
        List<UnVisitedUrlsModel> list = new ArrayList<>();

        String selectSQL = "SELECT id,root_url,unvisited_url FROM "+ AnalyseHostResultTable.tableName + " WHERE unvisited_url_num > 0 ORDER BY id ASC Limit ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            stmt.setInt(1, limit);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                UnVisitedUrlsModel unVisitedUrlsModel = new UnVisitedUrlsModel(
                        rs.getInt("id"),
                        rs.getString("root_url"),
                        rs.getString("unvisited_url")
                );
                list.add(unVisitedUrlsModel);
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] All UnVisited Urls: %s", AnalyseHostResultTable.tableName, e.getMessage()));
        }
        return list;
    }

    /**
     * 基于rootUrls查询对应的未访问URl
     */
    public static List<UnVisitedUrlsModel> fetchUnVisitedUrlsByRootUrls(List<String> rootUrls) {
        List<UnVisitedUrlsModel> arrayList = new ArrayList<>();

        if (rootUrls.isEmpty()) return arrayList;

        String selectSQL = ("SELECT id,root_url,unvisited_url FROM " + AnalyseHostResultTable.tableName +
                " WHERE root_url IN $buildInParamList$;")
                .replace("$buildInParamList$", SqlUtils.buildInParamList(rootUrls.size()));

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(selectSQL)) {
            for (int i = 0; i < rootUrls.size(); i++) {
                stmt.setString(i + 1, rootUrls.get(i));
            }

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                UnVisitedUrlsModel tabDataModel = new UnVisitedUrlsModel(
                        rs.getInt("id"),
                        rs.getString("root_url"),
                        rs.getString("unvisited_url")
                );
                arrayList.add(tabDataModel);
            }
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error fetch [%s] Result Data By MsgHash List: %s", AnalyseHostResultTable.tableName, e.getMessage()));
        }
        return arrayList;
    }

    /**
     * 实现 基于 ID 更新 unvisitedUrls
     */
    public static synchronized int updateUnVisitedUrlsByModel(UnVisitedUrlsModel unVisitedUrlsModel) {
        int affectedRows = -1; // 默认ID值，如果没有生成ID，则保持此值

        String updateSQL = "UPDATE " + AnalyseHostResultTable.tableName +"  SET unvisited_url = ?, unvisited_url_num = ? WHERE id = ?;";

        try (Connection conn = DBService.getInstance().getNewConn(); PreparedStatement stmt = conn.prepareStatement(updateSQL)) {
            stmt.setString(1, CastUtils.toJsonString(unVisitedUrlsModel.getUnvisitedUrls()));
            stmt.setInt(2, unVisitedUrlsModel.getUnvisitedUrls().size());
            stmt.setInt(3, unVisitedUrlsModel.getId());
            affectedRows = stmt.executeUpdate();
        } catch (Exception e) {
            stderr_println(LOG_ERROR, String.format("[-] Error update unvisited Urls By Id: %s", e.getMessage()));
        }
        return affectedRows;
    }
}
