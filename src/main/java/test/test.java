package test;

import java.util.*;

public class test {
    public static void main(String[] args) {
        System.out.println("HELLO");

        List<RespInfoComparisonModel> responses = new ArrayList<>();

        // 假设我们有以下响应信息
        RespInfoComparisonModel resp1 = new RespInfoComparisonModel(
                200,
                1024,
                2048,
                "404 NOT FOUND",
                "contentHash1",
                "redirect1"
        );

        RespInfoComparisonModel resp2 = new RespInfoComparisonModel(
                200,
                1024,
                2048,
                "404 NOT FOUND",
                "contentHash1",
                "redirect1"
        );

        RespInfoComparisonModel resp3 = new RespInfoComparisonModel(
                404,
                2048,
                4096,
                "404 NOT FOUND",
                "contentHash1",
                "redirect1"
        );

        responses.add(resp1);
        responses.add(resp2);
        responses.add(resp3);

        Map<String, Object> commonFields = RespInfoComparisonModel.findCommonFieldValues(responses);
        System.out.println("Common Fields: " + commonFields);
    }
}
