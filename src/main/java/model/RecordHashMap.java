package model;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.CRC32;

public class RecordHashMap {

    private final ConcurrentHashMap<String, Integer> countMap;

    public RecordHashMap() {
        this.countMap = new ConcurrentHashMap<>();
    }

    /**
     * 字符串转 CRC32
     */
    public static String calcCRC32(String string) {
        // 使用 UTF-8 编码将字符串转换为字节数组
        byte[] inputBytes = string.getBytes(StandardCharsets.UTF_8);
        return calcCRC32(inputBytes);
    }

    /**
     * 字符Byte[]转 CRC32
     */
    public static String calcCRC32(byte[] inputBytes) {
        // 初始化CRC32对象
        CRC32 crc32 = new CRC32();
        // 更新CRC值
        crc32.update(inputBytes, 0, inputBytes.length);
        // 将计算后的CRC32值转换为十六进制字符串并返回
        return Long.toHexString(crc32.getValue()).toLowerCase();
    }

    public Map<String, Integer> getStringMap() {
        return this.countMap;
    }

    public Integer get(String key) {
        Integer ret = this.countMap.get(key);
        if (ret == null) {
            return 0;
        } else {
            return ret;
        }
    }

    public void add(String key) {
        if (key == null || key.length() <= 0) {
            throw new IllegalArgumentException("Key 不能为空");
        }

        synchronized (this.getStringMap()) {
            this.countMap.put(key, (this.get(key) + 1));
        }
    }

    public void del(String key) {
        if (this.countMap.get(key) != null) {
            this.countMap.remove(key);
        }
    }
}
