package huahua.util;

import java.io.File;

public class EncodeUtil {
    private static String unicodeEncoding(final String gbString) {
        char[] utfBytes = gbString.toCharArray();
        String unicodeBytes = "";
        for (int i = 0; i < utfBytes.length; i++) {
            String hexB = Integer.toHexString(utfBytes[i]);
            if (hexB.length() <= 2) {
                hexB = "00" + hexB;
            }
            unicodeBytes = unicodeBytes + "\\u" + hexB;
        }
        return unicodeBytes;
    }

    private static String decodeUnicode(final String dataStr) {
        int start = 0;
        int end = 0;
        final StringBuffer buffer = new StringBuffer();
        while (start > -1) {
            end = dataStr.indexOf("\\u", start + 2);
            String charStr = "";
            if (end == -1) {
                charStr = dataStr.substring(start + 2, dataStr.length());
            } else {
                charStr = dataStr.substring(start + 2, end);
            }
            char letter = (char) Integer.parseInt(charStr, 16); // 16进制parse整形字符串。
            buffer.append(new Character(letter).toString());
            start = end;
        }
        return buffer.toString();
    }

    public static String reductionRelativePath(String path,String root){
        String separator = "/|\\\\";
        String encodeRelativePath=path.substring(root.length()+1);
        String[] names;
        names=encodeRelativePath.split(separator);                    //兼容windows和linux的分隔符
        StringBuilder relativePath=new StringBuilder();
        for (String name:names){
            if(name.length()!=0){
                relativePath.append(decodePath(name));
                relativePath.append(File.separator);
            }
        }
        return relativePath.substring(0,relativePath.length()-1);         //抛弃最后一个\\
    }

    /*
    * 由于jspc会对路径中不为java字符的字符进行unicode编码，为了将编译后的class和编译前的jsp名称能对上，这里需要将class的名字进行解码。才可以得到有问题的class其对应的jsp的名字。
    * */
    private static StringBuilder decodePath(String name){
        String[] jspNameArr=name.split("_");
        StringBuilder afterDecodeName=new StringBuilder();
        int num=0;
        for(String part:jspNameArr){
//            System.out.println(part);
            String afterDecode=null;
            try{afterDecode=EncodeUtil.decodeUnicode("\\u"+part.substring(0,4));}catch (Exception e){}
            if(part.length()>=4 && afterDecode !=null && ("\\u"+part.substring(0,4)).equals(EncodeUtil.unicodeEncoding(afterDecode))){
                afterDecodeName.append(afterDecode);
                afterDecodeName.append(part.substring(4));
            }else {
                if(num!=0){
                    afterDecodeName.append(".");
                }
                afterDecodeName.append(part);
            }
            ++num;
        }
        return afterDecodeName;
    }
}
