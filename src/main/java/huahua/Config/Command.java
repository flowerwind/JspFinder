package huahua.Config;

import com.beust.jcommander.Parameter;

public class Command {
    @Parameter(names = {"-h", "--help"}, description = "Help Info", help = true)
    public boolean help;

    @Parameter(names = {"-f", "--file"}, description = "指定web目录下的某个文件")
    public String file;

    @Parameter(names = {"-d", "--webDir"}, description = "指定web目录，如 D:\\tomcat环境\\apache-tomcat-8.0.50-windows-x64\\apache-tomcat-8.0.50\\webapps\\samples-web-1.2.4\\")
    public String webDir;

    @Parameter(names = {"--debug"}, description = "Debug")
    public boolean debug=false;

    @Parameter(names = {"-s", "--save"}, description = "指定结果存放的文件名")
    public String savePath="result.txt";
}
