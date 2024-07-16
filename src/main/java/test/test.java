package test;

import model.RespFieldsModel;
import utils.RespFieldCompareutils;

import java.util.*;

public class test {
    public static void main(String[] args) {
        System.out.println("HELLO");

        List<Map<String, Object>> fieldsMapList = new ArrayList<>();

        // 假设我们有以下响应信息
        RespFieldsModel resp1 = new RespFieldsModel(
                200,
                1024,
                2048,
                "404 NOT FOUND",
                "contentHash1",
                "redirect1"
        );

        RespFieldsModel resp2 = new RespFieldsModel(
                200,
                1024,
                2048,
                "404 NOT FOUND",
                "contentHash1",
                "redirect1"
        );

        RespFieldsModel resp3 = new RespFieldsModel(
                404,
                2048,
                4096,
                "404 NOT FOUND",
                "contentHash1",
                "redirect1"
        );

        fieldsMapList.add(resp1.getAllFieldsAsMap());
        fieldsMapList.add(resp2.getAllFieldsAsMap());
        fieldsMapList.add(resp3.getAllFieldsAsMap());

        Map<String, Object> commonFields = RespFieldCompareutils.findMapsSameFieldValue(fieldsMapList);
        System.out.println("Common Fields: " + commonFields);
    }
}
