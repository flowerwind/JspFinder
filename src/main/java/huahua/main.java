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

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;

//首先按照逆拓扑排序，把类中方法的调用进行排序
//排序完毕后，按照从前到后的顺序观察方法。如果调用危险了方法，如Runtime.exec或者ProcessBuilder的start方法，那么分析其参数是否被方法的入参所控制，如果被入参所控制，那么其就是一个危险方法。将方法名和哪几个参数能够污染做成Map放到ClassVisitor内部字段的队列中。
public class main {
    private static final Logger logger = Logger.getLogger(main.class);
    public static void main(String args[]){
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
    private static void start(Command command) {
        try {
            JspC jspc = new JspC();
            jspc.setCompile(true);
            jspc.setClassDebugInfo(false);
            jspc.setUriroot(command.webDir);
            FileUtil.mkAndClearJspCompile();
            jspc.setOutputDir("JspCompile");
            if (command.file != null) {
                jspc.setJspFiles(command.file);
            }
            jspc.execute();
            ArrayList<String> filenameList = new ArrayList<String>();
            ArrayList<String> classFileNameList = FileUtil.getAllClassFileName("JspCompile", filenameList);
            for(String classFileName : classFileNameList){
                //形成class文件和byte[]文件内容的对应
                byte[] classData=Files.readAllBytes(Paths.get(classFileName));
                Constant.classNameToByte.put(classFileName,classData);
                //形成class文件和被扫描的jsp之间的对应
                String rootPath=new File("JspCompile").getAbsolutePath()+File.separator+"org"+File.separator+"apache"+File.separator+"jsp";
                String relativeJspClassName= EncodeUtil.reductionRelativePath(classFileName,rootPath);
                String relativeJspName=relativeJspClassName.substring(0,relativeJspClassName.lastIndexOf("."));
                //webJspName为对应在web服务器上jsp文件的位置
                String webJspName=(command.webDir.substring(command.webDir.length()-1,command.webDir.length()).equals(File.separator) ? command.webDir : command.webDir+File.separator) + relativeJspName;
                Constant.classNameToJspName.put(classFileName,webJspName);
            }
            PassthroughDiscovery passthroughDiscovery =new PassthroughDiscovery();
            passthroughDiscovery.discover();
            FindEvilDiscovery findEvilDiscovery=new FindEvilDiscovery();
            findEvilDiscovery.discover();
            FileOutputStream fileOutputStream=new FileOutputStream(new File(command.savePath));
            for(String msg:Constant.msgList){
                fileOutputStream.write((msg+"\r\n").getBytes("utf-8"));
            }
            fileOutputStream.close();
        } catch (Exception e){
            e.printStackTrace();
        }
    }

}
