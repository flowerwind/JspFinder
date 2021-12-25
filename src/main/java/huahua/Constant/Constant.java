package huahua.Constant;

import huahua.data.MethodReference;

import java.util.*;

public class Constant {
   public static Map<String,byte[]> classNameToByte=new HashMap<>();
   public static Map<MethodReference.Handle, Set<Integer>> passthroughDataflow=new HashMap<>();
   public static Map<String, List<MethodReference.Handle>> classFileNameToSortedMethodCalls=new HashMap<>();
   public static Set<String> evilClass=new HashSet<String>();
   public static Map classNameToJspName=new HashMap();
   public static boolean debug=false;
}
