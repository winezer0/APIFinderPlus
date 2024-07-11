package database;

import burp.BurpExtender;
import org.sqlite.SQLiteConfig;
import utils.BurpFileUtils;

import java.sql.*;

import static utils.BurpPrintUtils.*;

public class DBService {
    //指定sqlite数据库配置文件路径
    private static final String CONNECTION_STRING = "jdbc:sqlite:" + BurpFileUtils.getPluginDirFilePath(BurpExtender.getCallbacks(), "APIFinder.db");
    private static DBService instance;
    private Connection connection;

    private DBService() {
        initDBConnection();
        initCreateTables();
    }

    public static synchronized DBService getInstance() {
        // 单例模式配置
        if (instance == null) {
            instance = new DBService();
        }
        return instance;
    }

    //创建数据库链接
    private void initDBConnection() {
        try {
            // 自动注册 SQLite 驱动程序
            Class.forName("org.sqlite.JDBC");

            // 建立数据库连接
            connection = DriverManager.getConnection(CONNECTION_STRING);

            // 启用外键支持
            try (Statement stmt = connection.createStatement()) {
                stmt.execute("PRAGMA foreign_keys = ON");
            } catch (SQLException e) {
                stderr_println(String.format("[!] set foreign_keys error. -> %s", e.getMessage()));
                e.printStackTrace();
            }

            stdout_println(LOG_INFO, "[+] SQLite database connection initialized successfully. ");
        } catch (ClassNotFoundException e) {
            stderr_println(String.format("[!] JDBC driver not found. -> %s", e.getMessage()));
            e.printStackTrace();
        } catch (SQLException e) {
            stderr_println(String.format("[!] Failed to connect db. -> %s", e.getMessage()));
            e.printStackTrace();
        }
    }

    //创建数据表结构
    private synchronized void initCreateTables() {
        // RecordUrlTable URL 访问记录表 用于后续排除已访问过的UR了
        execCreatTableSql(RecordUrlTable.creatTableSQL, RecordUrlTable.tableName);

        // RecordUrlsTable URL PATH记录表 用于后续路径猜测记录
        execCreatTableSql(RecordPathTable.creatTableSQL, RecordPathTable.tableName);

        // MsgDataTable 用于存储 实际的请求体和响应体
        execCreatTableSql(ReqMsgDataTable.creatTableSQL, ReqMsgDataTable.tableName);

        // reqDataTable 存储需要敏感信息提取的url
        execCreatTableSql(ReqDataTable.creatTableSQL, ReqDataTable.tableName);

        // 用来创建数据库 analyse_path 存储分析后的数据
        execCreatTableSql(AnalyseResultTable.creatTableSQL, AnalyseResultTable.tableName);

        // 创建存储根树的表
        execCreatTableSql(PathTreeTable.creatTableSQL, PathTreeTable.tableName);
    }

    //创建数据表的语句
    private void execCreatTableSql(String creatTableSql, String tableName) {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(creatTableSql);
            stdout_println(LOG_INFO, String.format("[+] create db %s success ...", tableName));
        } catch (Exception e) {
            stderr_println(String.format("[!] create db %s failed -> %s", tableName, e.getMessage()));
            e.printStackTrace();
        }
    }

    //获取一个数据库语句
    public Connection getNewConnection() throws SQLException {
        //解决 [SQLITE_BUSY] The database file is locked (database is locked) 错误
        SQLiteConfig config = new SQLiteConfig();
        config.setBusyTimeout(1000); // 设置超时时间，单位是毫秒
        return DriverManager.getConnection(CONNECTION_STRING, config.toProperties());
    }

    // 关闭数据库连接的方法
    public void closeConnection() {
        try {
            if (this.connection != null && !this.connection.isClosed()) {
                this.connection.close();
            }
        } catch (SQLException e) {
            stderr_println(String.format("关闭数据库连接时发生错误: %s", e.getMessage()));
            e.printStackTrace();
        }
    }

    /**
     * 清空表数据
     * @param tableName
     */
    private static void clearTable(String tableName) {
        // 用 DELETE 语句来清空表
        String deleteSql = "DELETE FROM tableName;"
                .replace("tableName", tableName);
        try (Connection conn = DBService.getInstance().getNewConnection();
             PreparedStatement stmt = conn.prepareStatement(deleteSql)) {
            stmt.executeUpdate();
            stdout_println(String.format("[-] table [%s] has been cleared.", tableName));
        } catch (Exception e) {
            stderr_println(String.format("Error clearing table [%s] -> Error: %s",tableName, e.getMessage()));
        }
    }

    /**
     * 清空所有表的数据
     */
    public static void clearAllTableData(){
       clearTable(AnalyseResultTable.tableName);
       clearTable(ReqDataTable.tableName);
       clearTable(ReqMsgDataTable.tableName);

//        clearTable(PathTreeTable.tableName);
//        clearTable(RecordPathTable.tableName);
//        clearTable(RecordUrlTable.tableName);
    }
}
