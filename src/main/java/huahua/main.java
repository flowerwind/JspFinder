package huahua;

import huahua.Config.Command;
import com.beust.jcommander.JCommander;
import huahua.Constant.Constant;
import huahua.Discovery.FindEvilDiscovery;
import huahua.Discovery.PassthroughDiscovery;
import huahua.util.EncodeUtil;
import huahua.util.FileUtil;
import org.apache.jasper.JspC;
import org.apache.log4j.Logger;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

//首先按照逆拓扑排序，把类中方法的调用进行排序
//排序完毕后，按照从前到后的顺序观察方法。如果调用危险了方法，如Runtime.exec或者ProcessBuilder的start方法，那么分析其参数是否被方法的入参所控制，如果被入参所控制，那么其就是一个危险方法。将方法名和哪几个参数能够污染做成Map放到ClassVisitor内部字段的队列中。
public class main {
    private static final Logger logger = Logger.getLogger(main.class);
    public static void main(String args[]) throws IOException {
        Command command = new Command();
        JCommander jc = JCommander.newBuilder().addObject(command).build();
        jc.parse(args);
        if (command.help) {
            jc.usage();
            return;
        }
        if(command.webDir==null){
            logger.error("web目录为空，请指定-d参数");
            return ;
        }
        Constant.debug=command.debug;
        start(command);
    }

    private static void start(Command command) throws IOException {

            Set<String> webDirSet=new HashSet<String>();
            getWebDir(command.webDir,webDirSet);
            for(String webDir:webDirSet){
                try {
                    //passthroughDataflow可以不用清除，passthroughDataflow清了要重新从磁盘读取一份，消耗资源，就算保留之前被分析的类的污染关系也无所谓，因为一般不会出现类名相同、方法名相同但方法内容不通的情况
                    Constant.evilClass.clear();
                    Constant.classNameToJspName.clear();
                    Constant.classFileNameToSortedMethodCalls.clear();
                    Constant.classNameToByte.clear();
                    JspC jspc = new JspC();
                    jspc.setCompile(true);
                    jspc.setClassDebugInfo(false);
                    jspc.setUriroot(webDir);
                    FileUtil.mkAndClearJspCompile();
                    jspc.setOutputDir("JspCompile");
                    ArrayList<String> jarFilePath=new ArrayList();
                    if(command.classPath!=null){
                        FileUtil.getJarFilePath(command.classPath,jarFilePath);
                        String classPath=null;
                        for(String jarFileName:jarFilePath){
                            classPath=classPath+File.pathSeparator+jarFileName;
                        }
                        jspc.setClassPath(classPath);
                    }
                    if (command.file != null) {
                        jspc.setJspFiles(command.file);
                    }
                    jspc.execute();
                    ArrayList<String> filenameList = new ArrayList<String>();
                    ArrayList<String> classFileNameList = FileUtil.getAllClassFileName("JspCompile", filenameList);
                    logger.info("开始扫描"+webDir);
//                    System.out.println("* * * * * * * * * * * * * * * * *"+"开始扫描"+webDir+"* * * * * * * * * * * * * * * * *");
                    for (String classFileName : classFileNameList) {
                        //形成class文件和byte[]文件内容的对应
                        byte[] classData = Files.readAllBytes(Paths.get(classFileName));
                        Constant.classNameToByte.put(classFileName, classData);
                        //形成class文件和被扫描的jsp之间的对应
                        String rootPath = new File("JspCompile").getAbsolutePath() + File.separator + "org" + File.separator + "apache" + File.separator + "jsp";
                        String relativeJspClassName = EncodeUtil.reductionRelativePath(classFileName, rootPath);
                        String relativeJspName = relativeJspClassName.substring(0, relativeJspClassName.lastIndexOf("."));
                        //webJspName为对应在web服务器上jsp文件的位置
                        String webJspName = (webDir.substring(webDir.length() - 1).equals(File.separator) ? webDir : webDir + File.separator) + relativeJspName;
                        Constant.classNameToJspName.put(classFileName, webJspName);
                    }
                    PassthroughDiscovery passthroughDiscovery = new PassthroughDiscovery();
                    passthroughDiscovery.discover();
                    FindEvilDiscovery findEvilDiscovery = new FindEvilDiscovery();
                    findEvilDiscovery.discover();
                    logger.info(webDir+"扫描结束");
//                    System.out.println("* * * * * * * * * * * * * * * * *"+webDir+"扫描结束* * * * * * * * * * * * * * * * *");
                    System.out.println("\r\n");
                }catch (java.io.FileNotFoundException e){
                    System.out.println("请求包jar包的根目录中包含Passthrough.dat文件");
                } catch (Exception e){
                    e.printStackTrace();
                    logger.info(webDir+"编译出错");
//                    System.out.println("- - - - - - - - - - - - - - - - -"+webDir+"编译出错"+"- - - - - - - - - - - - - - - - -");
                    System.out.println("\r\n");
                }
            }
            //删除编译文件
            FileUtil.deleteDir(new File("JspCompile"));
            //保存检测结果
            saveResult(command.savePath);

    }

    private static void getWebDir(String webDir,Set<String> webDirSet){
//        File [] files = new File(webDir).listFiles();
        ArrayList<String> allFileName=new ArrayList<String>();
        FileUtil.getAllFileName(webDir,allFileName);
        for(String filename:allFileName){
            String tag=File.separator+"WEB-INF"+File.separator;
            int point=filename.indexOf(tag);
            if(point>-1){
                webDirSet.add(filename.substring(0,point));
            }
        }
    }

    private static void saveResult(String savePath) throws IOException {
        FileOutputStream fileOutputStream=new FileOutputStream(new File(savePath));
        for(String msg:Constant.msgList){
            fileOutputStream.write((msg+"\r\n").getBytes("utf-8"));
        }
        fileOutputStream.close();
    }

}
