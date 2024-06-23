package dataModel;

import java.sql.*;

import static utils.BurpPrintUtils.*;

public class PathTreeTable {
    //数据表名称
    static String tableName = "path_tree";

    //创建 基于 record_urls 生成的每个域名的 路径结构 树
    static String creatTableSQL = "CREATE TABLE IF NOT EXISTS tableName (\n"
            .replace("tableName", tableName)
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"  //自增的id
            + " req_host TEXT NOT NULL,\n"    //请求域名
            + " req_port TEXT NOT NULL,\n"    //请求端口
            + " path_tree TEXT NOT NULL,\n"   //根树的序列化Json数据
            + " basic_path_num INTEGER NOT NULL DEFAULT 0\n"  //基于多少个路径计算出来的根树,最好使用根树的稳定 hash
            + ");";

    //插入数据库
    public static synchronized int insertOrUpdatePathTree(String reqHost, String reqPort, String pathTree, int basicPathNum) {
        DBService dbService = DBService.getInstance();
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id, basic_path_num FROM tableName WHERE req_host = ? AND req_port = ?"
                .replace("tableName", tableName);

        try (Connection conn = dbService.getNewConnection();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {

            checkStmt.setString(1, reqHost);
            checkStmt.setString(2, reqPort);

            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在
                int selectedIndex = rs.getInt("id");
                int oldBasicPathNum = rs.getInt("basic_path_num");

                // 当 basic_path_num 大于 查询获取到的 old_basic_path_num 时 说明获取到了新的Path 需要更新数据
                if (basicPathNum > oldBasicPathNum){
                    String updateSQL = "UPDATE tableName SET path_tree = ?,basic_path_num = ?  WHERE id = ?;"
                            .replace("tableName", tableName);

                    //更新索引对应的数据
                    try (PreparedStatement updateStatement = conn.prepareStatement(updateSQL)) {
                        updateStatement.setString(1, pathTree);
                        updateStatement.setInt(2, basicPathNum);
                        updateStatement.setInt(3, selectedIndex);
                        int affectedRows = updateStatement.executeUpdate();
                        if (affectedRows > 0) {
                            generatedId = selectedIndex;
                        }
                    }
                } else {
                    stdout_println(LOG_INFO, String.format("[*] Ignore Update [%s] %s -> %s", tableName, reqHost, reqPort));
                    return 0;
                }
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO tableName (req_host, req_port, path_tree, basic_path_num) VALUES (?, ?, ?, ?)"
                        .replace("tableName", tableName);

                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, reqHost);
                    insertStmt.setString(2, reqPort);
                    insertStmt.setString(3, pathTree);
                    insertStmt.setInt(4, basicPathNum);
                    insertStmt.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = insertStmt.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            generatedId = generatedKeys.getInt(1); // 获取生成的ID
                        }
                    }
                }
            }
        } catch (Exception e) {
            stderr_println(String.format("[-] Error inserting or updating table [%s] -> Error:[%s]", tableName, reqHost, reqPort));
            e.printStackTrace();
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }

}
