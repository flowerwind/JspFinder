package huahua.Config;

import com.beust.jcommander.Parameter;

public class Command {
    @Parameter(names = {"-h", "--help"}, description = "Help Info", help = true)
    public boolean help;

    @Parameter(names = {"-f", "--file"}, description = "指定web目录下的某个文件")
    public String file;

//    @Parameter(names = {"-m", "--module"}, description = "Scan Module")
//    public String module;
@Parameter(names = {"-d","--webDir"}, description = "web目录")
public String webDir;


    @Parameter(names = {"--debug"}, description = "Debug")
    public boolean debug;
}
