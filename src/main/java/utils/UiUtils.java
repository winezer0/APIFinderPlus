package utils;

import burp.IHttpService;
import model.TableLineDataModel;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;

import static utils.BurpPrintUtils.stderr_println;

public class UiUtils {
    public static ImageIcon getImageIcon(String iconPath, int xWidth, int yWidth){
        // 根据按钮的大小缩放图标
        URL iconURL = UiUtils.class.getResource(iconPath);
        ImageIcon originalIcon = new ImageIcon(iconURL);
        Image img = originalIcon.getImage();
        Image newImg = img.getScaledInstance(xWidth, yWidth, Image.SCALE_SMOOTH);
        return new ImageIcon(newImg);
    }

    public static ImageIcon getImageIcon(String iconPath){
        // 根据按钮的大小缩放图标
        URL iconURL = UiUtils.class.getResource(iconPath);
        ImageIcon originalIcon = new ImageIcon(iconURL);
        Image img = originalIcon.getImage();
        Image newImg = img.getScaledInstance(17, 17, Image.SCALE_SMOOTH);
        return new ImageIcon(newImg);
    }

    public static String encodeForHTML(String input) {
        if(input == null) {
            return "";
        }
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }

    public static IHttpService getIHttpService(String host, int port, String protocol){
        return new IHttpService() {
            @Override
            public String getHost() {
                return host;
            }

            @Override
            public int getPort() {
                return port;
            }

            @Override
            public String getProtocol() {
                return protocol;
            }
        };
    }

    public static IHttpService getIHttpService(String url){
        try {
            URL urlObj = new URL(url);
            //获取请求协议
            String protocol = urlObj.getProtocol();
            //从URL中获取请求host
            String host = urlObj.getHost();
            //从URL中获取请求Port
            int port = urlObj.getPort();
            return getIHttpService(host, port, protocol);
        } catch (MalformedURLException e) {
            stderr_println(String.format("URL格式不正确: %s -> %s", url, e.getMessage()));
            return null;
        }
    }


    /**
     * 把 jsonArray 赋值到 model 中
     * @param model
     * @param jsonArray
     */
    public static void populateModelFromJsonArray(DefaultTableModel model, ArrayList<TableLineDataModel> jsonArray) {
        if (jsonArray.isEmpty()) return;

        Iterator<TableLineDataModel> iterator = jsonArray.iterator();
        while (iterator.hasNext()) {
            TableLineDataModel apiDataModel = iterator.next();
            Object[] rowData = apiDataModel.toRowDataArray();
            model.addRow(rowData);
        }
        //刷新表数据模型
        model.fireTableDataChanged();
    }
}
