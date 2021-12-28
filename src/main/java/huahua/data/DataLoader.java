package huahua.data;

import com.google.common.io.Files;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;

public class DataLoader {
    public static <T> List<T> loadData(String filePath, DataFactory<T> factory) throws IOException, ClassNotFoundException {
        InputStream is=Class.forName("huahua.main").getResourceAsStream(filePath);
        BufferedReader br=new BufferedReader(new InputStreamReader(is));
        String s="";
        final List<T> values = new ArrayList<T>();
        while((s=br.readLine())!=null){
            values.add(factory.parse(s.split("\t", -1)));
    }
//        final List<String> lines = Files.readLines(filePath, StandardCharsets.UTF_8);
//        final List<T> values = new ArrayList<T>(lines.size());
//        for (String line : lines) {
//            values.add(factory.parse(line.split("\t", -1)));
//        }
        return values;
    }

    public static <T> void saveData(Path filePath, DataFactory<T> factory, Collection<T> values) throws IOException {
        try (BufferedWriter writer = Files.newWriter(filePath.toFile(), StandardCharsets.UTF_8)) {
            for (T value : values) {
                final String[] fields = factory.serialize(value);
                if (fields == null) {
                    continue;
                }

                StringBuilder sb = new StringBuilder();
                for (String field : fields) {
                    if (field == null) {
                        sb.append("\t");
                    } else {
                        sb.append("\t").append(field);
                    }
                }
                writer.write(sb.substring(1));
                writer.write("\n");
            }
        }
    }

    /**
     * 从classes.dat加载类信息
     *
     * @return
     */
//    public static Map<ClassReference.Handle, ClassReference> loadClasses() {
//        try {
//            Map<ClassReference.Handle, ClassReference> classMap = new HashMap<>();
//            for (ClassReference classReference : loadData(Paths.get("classes.dat"), new ClassReference.Factory())) {
//                classMap.put(classReference.getHandle(), classReference);
//            }
//            return classMap;
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//    }

//    /**
//     * 从methods.dat加载所有方法信息
//     *
//     * @return
//     */
//    public static Map<String, MethodReference> loadMethods() {
//        try {
//            Map<String, MethodReference> methodMap = new HashMap<>();
//            for (MethodReference methodReference : loadData(Paths.get("methods.dat"), new MethodReference.Factory())) {
//                methodMap.put(methodReference.getOwner(), methodReference);
//            }
//            return methodMap;
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//    }

    /**
     * 从slinks.dat加载特殊的slink信息
     *
     * @return
     */
//    public static Map<ClassReference.Handle, Set<MethodReference>> loadSlinks() {
//        try {
//            Map<ClassReference.Handle, Set<MethodReference>> methodMap = new HashMap<>();
//            for (SlinkReference slinkReference : loadData(Paths.get("slinks.dat"), new SlinkFactory())) {
//                methodMap.put(slinkReference.getClassReference(), slinkReference.getMethodReferences());
//            }
//            return methodMap;
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        return Collections.EMPTY_MAP;
//    }
}
