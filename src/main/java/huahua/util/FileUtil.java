package huahua.util;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;

public class FileUtil {
    public static void mkAndClearJspCompile(){
        File file=new File("JspCompile");
        if(file.exists()){
            deleteDir(file);
        }
        file.mkdir();
    }

    //递归删除文件夹
    private static boolean deleteDir(File dir) {
        if (dir.isDirectory()) {
            String[] children = dir.list();
            for (int i=0; i<children.length; i++) {
                boolean success = deleteDir(new File(dir, children[i]));
                if (!success) {
                    return false;
                }
            }
        }
        // 目录此时为空，可以删除
        return dir.delete();
    }

    public static void getAllFileName(String path, ArrayList<String> fileNameList)
    {
        File file = new File(path);
        File [] files = file.listFiles();
        for(File a:files)
        {
            if(a.isDirectory())
            {
                getAllFileName(a.getAbsolutePath(),fileNameList);
            }else{
                fileNameList.add(a.getAbsolutePath());
            }
        }
    }

    public static ArrayList<String> getAllClassFileName(String path, ArrayList<String> fileNameList){
        getAllFileName(path,fileNameList);
        ArrayList<String> classFileNameList=new ArrayList<String>();
        for(String filename:fileNameList){
            int point=filename.lastIndexOf(".");
            String suffix=filename.substring(point);
            if(suffix.equals(".class")){
                classFileNameList.add(filename);
            }
        }
        return classFileNameList;
    }

    public static void main(String args[]){
        ArrayList<String> filenameList=new ArrayList<String>();
        ArrayList<String> classFileNameList =getAllClassFileName("JspCompile",filenameList);
        for(String filename:classFileNameList){
            System.out.println(filename);
        }
    }
}
