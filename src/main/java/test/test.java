package test;

import utils.RespInfoCompareUtils;

import java.util.*;

public class test {
    public static void main(String[] args) {
        System.out.println("HELLO");

        List<RespInfoCompareModel> responses = new ArrayList<>();

        // 假设我们有以下响应信息
        RespInfoCompareModel resp1 = new RespInfoCompareModel(
                200,
                1024,
                2048,
                "404 NOT FOUND",
                "contentHash1",
                "redirect1"
        );

        RespInfoCompareModel resp2 = new RespInfoCompareModel(
                200,
                1024,
                2048,
                "404 NOT FOUND",
                "contentHash1",
                "redirect1"
        );

        RespInfoCompareModel resp3 = new RespInfoCompareModel(
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

        Map<String, Object> commonFields = RespInfoCompareUtils.findCommonFieldValues(responses);
        System.out.println("Common Fields: " + commonFields);
    }
}
