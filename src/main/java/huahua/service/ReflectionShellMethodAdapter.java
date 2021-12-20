package huahua.service;

import com.sun.org.apache.xpath.internal.compiler.OpCodes;
import huahua.core.CoreMethodAdapter;
import jdk.nashorn.internal.runtime.regexp.joni.constants.OPCode;
import org.apache.log4j.Logger;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;


import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ReflectionShellMethodAdapter extends CoreMethodAdapter<String> {
    private Logger logger = Logger.getLogger(ReflectionShellMethodAdapter.class);

    private final int access;
    private final String desc;
    private final Map<String, List<Boolean>> analysisData;

    public ReflectionShellMethodAdapter(int api, MethodVisitor mv, String owner,
                                        int access, String name, String desc,
                                        String signature, String[] exceptions,
                                        Map<String, List<Boolean>> analysisData) {
        super(api, mv, owner, access, name, desc, signature, exceptions);
        this.access = access;
        this.desc = desc;
        this.analysisData = analysisData;
    }

    @Override
    public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
        if (opcode == Opcodes.INVOKEINTERFACE) {
            boolean getParam = name.equals("getParameter") &&
                    owner.equals("javax/servlet/http/HttpServletRequest") &&
                    desc.equals("(Ljava/lang/String;)Ljava/lang/String;");
            boolean arrayListAdd=name.equals("add") && owner.equals("java/util/List");
            if (arrayListAdd){
                int k=0;
                boolean get_param_true=false;
                for (Type argType : Type.getArgumentTypes(desc)) {
                    int size=argType.getSize();
                    while (size-- > 0){
                        if (operandStack.get(k).contains("get-param")){
                            get_param_true=true;
                        }
                        k++;
                    }
                }
                if(get_param_true){
                    operandStack.get(k).add("get-param");             //所有参数过完之后k就来到了操作数栈中的list对象的位置，如果add方法参数包含可被攻击者控制的值，则list对象添加get-param污点
                }
                super.visitMethodInsn(opcode, owner, name, desc, itf);
                return ;
            }
            if (getParam) {
                super.visitMethodInsn(opcode, owner, name, desc, itf);
                logger.info("find source: request.getParameter");
                operandStack.get(0).add("get-param");                //运算完super.visitMethodInsn之后，操作数栈最外侧得为getParameter方法返回的值
                return;
            }
        }
        if (opcode == Opcodes.INVOKESTATIC) {
            boolean forName = name.equals("forName") &&
                    owner.equals("java/lang/Class") &&
                    desc.equals("(Ljava/lang/String;)Ljava/lang/Class;");
            if (forName) {
                if (operandStack.get(0).contains("ldc-runtime")) {                    //如果Class.forName的参数为Runtime的话(ldc-runtime在visitLdcInsn阶段标记)，进入循环
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    logger.info("-> get Runtime class");
                    operandStack.get(0).add("class-runtime");                        //标记Class.forname("Runtime.class")的这个类为class-runtime
                    return;
                }
            }
        }
        if (opcode==Opcodes.INVOKESPECIAL){
            boolean processBuilderInit=owner.equals("java/lang/ProcessBuilder")&&name.equals("<init>");
            if (processBuilderInit){
                if (operandStack.get(0).contains("get-param")){
                    logger.info("发现java ProcessBuilder webshell！！！");
                }
            }
        }
        if (opcode == Opcodes.INVOKEVIRTUAL) {
            boolean decodeBuffer=name.equals("decodeBuffer") && owner.equals("sun/misc/BASE64Decoder") && desc.equals("(Ljava/lang/String;)[B");
            boolean getMethod = name.equals("getMethod") &&
                    owner.equals("java/lang/Class") &&
                    desc.equals("(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");

            boolean invoke = name.equals("invoke") &&
                    owner.equals("java/lang/reflect/Method") &&
                    desc.equals("(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
            boolean append = name.equals("append") &&
                    owner.equals("java/lang/StringBuilder") &&
                    desc.equals("(Ljava/lang/String;)Ljava/lang/StringBuilder;");
            boolean toString = name.equals("toString") &&
                    owner.equals("java/lang/StringBuilder") &&
                    desc.equals("()Ljava/lang/String;");
            boolean exec=name.equals("exec")&& owner.equals("java/lang/Runtime")&desc.contains("Ljava/lang/Process");     //把desc修改为包含返回值为Process的即为发现Runtime.exec方法，这样可以同时检测到重载的几个方法

            if(decodeBuffer){
                try {
                    Field name1 =CoreMethodAdapter.class.getDeclaredField("name");
                    name1.setAccessible(true);
                    String methodName=(String) name1.get(this);
                    if(methodName.equals("getPicture")){
                        System.out.println(operandStack.get(0).size());
                    }
                }catch (Exception e){

                }
            }

            if (append) {
                if (operandStack.get(0).size() != 0) {
                    String before = null;
                    if (operandStack.get(1).size() != 0) {
                        before = new ArrayList<>(operandStack.get(1)).get(0);
                    }
                    if (before == null) {
                        before = new ArrayList<>(operandStack.get(0)).get(0);
                    } else {
                        before += new ArrayList<>(operandStack.get(0)).get(0);
                    }
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).add(before);
                    return;
                }
            }
            if (toString) {
                if (operandStack.get(0).size() != 0) {
                    List<String> data = new ArrayList<>(operandStack.get(0));
                    StringBuilder builder = new StringBuilder();
                    for (String s : data) {
                        builder.append(s);
                    }
                    String result = builder.toString();
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    if (result.equals("get-param")){
                        operandStack.get(0).add("get-param");
                    }
                    if (result.equals("exec")) {
                        operandStack.get(0).add("ldc-exec");
                    }
                    if (result.equals("getRuntime")) {
                        operandStack.get(0).add("ldc-get-runtime");
                    }
                    return;
                }
            }
            if (getMethod) {
                if (operandStack.get(1).contains("ldc-get-runtime")) {
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    logger.info("-> get getRuntime method");
                    operandStack.get(0).add("method-get-runtime");
                    return;
                }
                if (operandStack.get(1).contains("ldc-exec")) {
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    logger.info("-> get exec method");
                    operandStack.get(0).add("method-exec");
                    return;
                }
            }
            if (invoke) {
                if (operandStack.get(0).contains("get-param")) {
                    if (operandStack.get(2).contains("method-exec")) {
                        logger.info("find reflection webshell!");
                        super.visitMethodInsn(opcode, owner, name, desc, itf);
                        return;
                    }
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    logger.info("-> invoke方法参数可控");
                    return;
                }
            }
            if (exec) {
                if (operandStack.get(0).contains("get-param")){
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    logger.info("发现java Runtime.exec webshell！！！");
                    return ;
                }
            }
        }
        super.visitMethodInsn(opcode, owner, name, desc, itf);
    }

//    @Override
//    public void visitTypeInsn(int opcode, String type) {
//        if(opcode== Opcodes.NEW){
//            try {
//                Field name =CoreMethodAdapter.class.getDeclaredField("name");
//                name.setAccessible(true);
//                String methodName=(String) name.get(this);
//                if(methodName.equals("getPicture")){
//                    super.visitTypeInsn(opcode,type);
//                    System.out.println(operandStack.get(0).size());
//                    if(operandStack.get(0)!=null){
//                        System.out.println(operandStack.get(0).size());
//                    }
//                    return;
//                }
//            } catch (NoSuchFieldException | IllegalAccessException e) {
//                e.printStackTrace();
//            }
//        }
//        super.visitTypeInsn(opcode,type);
//    }

    @Override
    public void visitInsn(int opcode) {
        if (opcode == Opcodes.AASTORE) {
            if (operandStack.get(0).contains("get-param")) {
                logger.info("store request param into array");
                super.visitInsn(opcode);
                operandStack.get(0).clear();
                operandStack.get(0).add("get-param");
                return;
            }
        }
        super.visitInsn(opcode);
    }

    @Override
    public void visitLdcInsn(Object cst) {
        if (cst.equals("java.lang.Runtime")) {
            super.visitLdcInsn(cst);
            operandStack.get(0).add("ldc-runtime");
            return;
        }
        if (cst.equals("getRuntime")) {
            super.visitLdcInsn(cst);
            operandStack.get(0).add("ldc-get-runtime");
            return;
        }
        if (cst.equals("exec")) {
            super.visitLdcInsn(cst);
            operandStack.get(0).add("ldc-exec");
            return;
        }
        if (cst instanceof String) {
            super.visitLdcInsn(cst);
            operandStack.get(0).add((String) cst);
            return;
        }
        super.visitLdcInsn(cst);
    }
}
