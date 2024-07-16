package test;

import utils.RespCompareUtils;

import java.util.*;

public class test {
    public static void main(String[] args) {
        System.out.println("HELLO");

        List<RespCompareModel> responses = new ArrayList<>();

        // 假设我们有以下响应信息
        RespCompareModel resp1 = new RespCompareModel(
                200,
                1024,
                2048,
                "404 NOT FOUND",
                "contentHash1",
                "redirect1"
        );

        RespCompareModel resp2 = new RespCompareModel(
                200,
                1024,
                2048,
                "404 NOT FOUND",
                "contentHash1",
                "redirect1"
        );

        RespCompareModel resp3 = new RespCompareModel(
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

        Map<String, Object> commonFields = RespCompareUtils.findCommonFieldValues(responses);
        System.out.println("Common Fields: " + commonFields);
    }
}
