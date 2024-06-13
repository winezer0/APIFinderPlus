package utilbox;

import java.nio.charset.Charset;

public class ByteArrayUtils {


    /**
     * byte[]数组截取
     * srcPoC 是原数组的起始位置，length是要截取的长度
     */
    public static byte[] subByte(byte[] b, int srcPos, int length) {
        byte[] b1 = new byte[length];
        System.arraycopy(b, srcPos, b1, 0, length);
        return b1;
    }


    public static String getSystemCharSet() {
        return Charset.defaultCharset().toString();

        //system_println(System.getProperty("file.encoding"));
    }


    /**
     * 将10进制转换为16进制
     *
     * @param decimal 10进制
     * @return 16进制
     */
    public static String decimalToHex(int decimal) {
        String hex = Integer.toHexString(decimal);
        return hex.toUpperCase();
    }


    /**
     * 拼接多个byte[]数组的方法
     *
     * @param arrays
     * @return
     */
    public static byte[] join(byte[]... arrays) {
        int len = 0;
        for (byte[] arr : arrays) {
            len += arr.length;//计算多个数组的长度总和
        }

        byte[] result = new byte[len];
        int idx = 0;

        for (byte[] arr : arrays) {
            for (byte b : arr) {
                result[idx++] = b;
            }
        }

        return result;
    }


    /**
     * https://stackoverflow.com/questions/21341027/find-indexof-a-byte-array-within-another-byte-array
     * Search the data byte array for the first occurrence
     * of the byte array pattern.
     */
    public static int BytesIndexOf(byte[] data, byte[] pattern) {
        int[] failure = computeFailure(pattern);

        int j = 0;

        for (int i = 0; i < data.length; i++) {
            while (j > 0 && pattern[j] != data[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == data[i]) {
                j++;
            }
            if (j == pattern.length) {
                return i - pattern.length + 1;
            }
        }
        return -1;
    }

    /**
     * Computes the failure function using a boot-strapping process,
     * where the pattern is matched against itself.
     */
    private static int[] computeFailure(byte[] pattern) {
        int[] failure = new int[pattern.length];

        int j = 0;
        for (int i = 1; i < pattern.length; i++) {
            while (j > 0 && pattern[j] != pattern[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == pattern[i]) {
                j++;
            }
            failure[i] = j;
        }

        return failure;
    }

    public static boolean equals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }

        if (a.length != b.length) {
            return false;
        }

        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }
}
