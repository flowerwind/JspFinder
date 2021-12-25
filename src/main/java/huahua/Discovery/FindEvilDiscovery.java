package huahua.Discovery;

import huahua.Constant.Constant;
import huahua.core.CoreMethodAdapter;
import huahua.data.MethodReference;
import org.apache.log4j.Logger;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.JSRInlinerAdapter;

import java.io.IOException;
import java.util.*;

public class FindEvilDiscovery {
    private static final Logger logger = Logger.getLogger(FindEvilDiscovery.class);

    public void discover(){
        findEvilDataflow();
    }
    private void findEvilDataflow(){
        final Map<MethodReference.Handle, Set<Integer>> EvilDataflow = new HashMap<>();
        for(String  classFileName:Constant.classFileNameToSortedMethodCalls.keySet()){
            List<MethodReference.Handle> methodCalls=Constant.classFileNameToSortedMethodCalls.get(classFileName);
            for(MethodReference.Handle methodToVisit:methodCalls){
                byte[] classByte=Constant.classNameToByte.get(classFileName);
                ClassReader cr=new ClassReader(classByte);
                FindEvilDataflowClassVisitor findEvilDataflowClassVisitor=new FindEvilDataflowClassVisitor(EvilDataflow,Opcodes.ASM6,methodToVisit,classFileName);
                cr.accept(findEvilDataflowClassVisitor,ClassReader.EXPAND_FRAMES);
            }
        }

    }

    private class FindEvilDataflowClassVisitor extends ClassVisitor{
        private FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor;
        private final Map<MethodReference.Handle, Set<Integer>> EvilDataflow;
        private final MethodReference.Handle methodToVisit;
        private String name;
        private String classFileName;
        private Set printEvilMessage=new HashSet();
        public FindEvilDataflowClassVisitor(Map<MethodReference.Handle, Set<Integer>> EvilDataflow,int api,MethodReference.Handle methodToVisit,String classFileName){
            super(api);
            this.EvilDataflow=EvilDataflow;
            this.methodToVisit=methodToVisit;
            this.classFileName=classFileName;
        }



        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            this.name = name;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            //对method进行观察
            MethodVisitor mv=super.visitMethod(access, name, descriptor, signature, exceptions);
            if(name.equals(this.methodToVisit.getName())){
                if(Constant.debug){
                    logger.info("观察的类为:"+this.name+"     观察的方法为:"+name);
                }
                findEvilDataflowMethodVisitor=new FindEvilDataflowMethodVisitor(EvilDataflow,Opcodes.ASM6,access,descriptor,mv,this.name,name,signature,exceptions,classFileName,printEvilMessage);
                EvilDataflow.put(new MethodReference.Handle(this.name,name,descriptor),getReturnTaint());
                return new JSRInlinerAdapter(findEvilDataflowMethodVisitor, access, name, descriptor, signature, exceptions);
            }
            return super.visitMethod(access,name,descriptor,signature,exceptions);
        }

        public Set<Integer> getReturnTaint() {
            if (findEvilDataflowMethodVisitor == null) {
                throw new IllegalStateException("Never constructed the passthroughDataflowmethodVisitor!");
            }
            return findEvilDataflowMethodVisitor.toEvilTaint;
        }
    }

    private class FindEvilDataflowMethodVisitor extends CoreMethodAdapter {
        private final Set<Integer> toEvilTaint;//被污染的返回数据
        private final Map<MethodReference.Handle, Set<Integer>> EvilDataflow;
        private final int access;
        private final String desc;
        private final String owner;
        private final String name;
        private final boolean isStatic;
        private String classFileName;
        private Set printEvilMessage;
        public FindEvilDataflowMethodVisitor(Map<MethodReference.Handle, Set<Integer>> EvilDataflow,int api,int access,String desc,MethodVisitor mv,String owner,String name,String signature,String[] exceptions,String classFileName,Set printEvilMessage){
            super(api,mv,owner,access,name,desc,signature,exceptions);
            this.EvilDataflow=EvilDataflow;
            this.toEvilTaint=new HashSet<>();
            this.access = access;
            this.desc = desc;
            this.owner=owner;
            this.name=name;
            this.isStatic=(access & Opcodes.ACC_STATIC)!=0;
            this.classFileName=classFileName;
            this.printEvilMessage=printEvilMessage;
        }

        @Override
        public void visitCode() {
            super.visitCode();

            int localIndex = 0;
            int argIndex = 0;
            if ((this.access & Opcodes.ACC_STATIC) == 0) {
                //非静态方法，第一个局部变量应该为对象实例this
                //添加到本地变量表集合
                setLocalTaint(localIndex, argIndex);
                localIndex += 1;
                argIndex += 1;
            }
            for (Type argType : Type.getArgumentTypes(desc)) {
                //判断参数类型，得出变量占用空间大小，然后存储
                setLocalTaint(localIndex, argIndex);
                localIndex += argType.getSize();
                argIndex += 1;
            }
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            Type[] argTypes = Type.getArgumentTypes(desc);
            //获取返回值类型大小
            int retSize = Type.getReturnType(desc).getSize();
            Set<Integer> resultTaint;
            switch (opcode){
                case Opcodes.INVOKESTATIC:
                case Opcodes.INVOKEINTERFACE:
                case Opcodes.INVOKEVIRTUAL:
                case Opcodes.INVOKESPECIAL:
                    //todo 处理调用恶意方法的情况
                    //非静态方法需要把实例类型放在第一个元素
                    if (opcode != Opcodes.INVOKESTATIC) {
                        Type[] extendedArgTypes = new Type[argTypes.length+1];
                        System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
                        extendedArgTypes[0] = Type.getObjectType(owner);
                        argTypes = extendedArgTypes;
                    }
                    final List<Set<Integer>> argTaint = new ArrayList<Set<Integer>>(argTypes.length);
                    for (int i = 0; i < argTypes.length; i++) {
                        argTaint.add(null);
                    }

                    int stackIndex = 0;
                    for (int i = 0; i < argTypes.length; i++) {
                        Type argType = argTypes[i];
                        if (argType.getSize() > 0) {
                            //栈顶对应被调用方法最右边的参数
                            argTaint.set(argTypes.length - 1 - i, operandStack.get(stackIndex + argType.getSize() - 1));
                        }
                        stackIndex += argType.getSize();
                    }

                    // 构造方法的调用，意味参数0可以污染返回值
                    if (name.equals("<init>")) {
                        // Pass result taint through to original taint set; the initialized object is directly tainted by
                        // parameters
                        resultTaint = argTaint.get(0);
                    } else {
                        resultTaint = new HashSet<>();
                    }


                    //调用之前PassthroughDiscovery的污染结果，看当前调用到的类是否可以污染，如果可以污染把被哪个参数污染的结果传递下去
                    Set<Integer> passthrough = Constant.passthroughDataflow.get(new MethodReference.Handle(owner, name, desc));
                    if(passthrough !=null&&passthrough.size()>0){
                        for (Integer passthroughDataflowArg : passthrough) {
                            resultTaint.addAll(argTaint.get(new Integer(passthroughDataflowArg)));
                        }
                    }

                    // 前面已做逆拓扑，调用链最末端最先被visit，因此，调用到的方法必然已被visit分析过
                    Set<Integer> evilMethodDataflow = EvilDataflow.get(new MethodReference.Handle(owner, name, desc));
                    if (evilMethodDataflow != null && evilMethodDataflow.size()>0) {
                        for (Integer evilMethodDataflowArg : evilMethodDataflow) {
                            //表示argTaint.get(new Integer(evilMethodDataflowArg))里的那个值对应的参数能污染到危险方法
                            toEvilTaint.addAll(argTaint.get(new Integer(evilMethodDataflowArg)));
                        }
                        //如果大于0表示调用方法可以污染到被调用方法
                       if(toEvilTaint.size()>0){
                            // 如果调用方法为_jspService，并且污染值在第一位(request参数是_jspService方法第一位，说明恶意类可以被request污染--也就是攻击者可控)
                            if(this.name.equals("_jspService") && toEvilTaint.contains(1)){
                                //printEvilMessage中如果包含1，则表示该类已经被标记为webshell，并且已经输出告警。如果包含1的话则不要再重复输出告警了。
                                if (!printEvilMessage.contains(1))
                                    printEvilMessage.add(1);
                                logger.info(Constant.classNameToJspName.get(classFileName) + "恶意类如(Runtime、ProcessBuilder)可被request污染，该文件为webshell!!!");
                                Constant.evilClass.add(classFileName);
                            }
                            if(Constant.debug){
                                logger.info("类:"+this.owner+"方法:"+this.name+"调用到被污染方法:"+name);
                                logger.info("污染点为:"+toEvilTaint);
                            }
                        }
                    }
                    break;
                default:
                    throw new IllegalStateException("Unexpected value: " + opcode);
            }
            //调用实例方法
            if(opcode==Opcodes.INVOKEVIRTUAL){
                //下面这些bool判断出了Runtime exc的，其他都是看有没有调用到字符串处理的方法，如果有字符串处理的方法，把污点传递(污点中包含字符串明文，传递到一些方法中会做对应模拟处理，比如append会把污点中的字符串相加)
                boolean subString=owner.equals("java/lang/String")&&name.equals("substring");
                boolean classCallMethod=owner.equals("java/lang/Class")&&(name.equals("getMethod")||name.equals("getConstructors")||name.equals("getConstructor")||name.equals("getDeclaredConstructors")||name.equals("getDeclaredConstructor")||name.equals("getDeclaredMethod"));
                boolean decodeBuffer=name.equals("decodeBuffer") && owner.equals("sun/misc/BASE64Decoder") && desc.equals("(Ljava/lang/String;)[B");
                boolean exec=name.equals("exec")&& owner.equals("java/lang/Runtime")&desc.contains("Ljava/lang/Process");     //把desc修改为包含返回值为Process的即为发现Runtime.exec方法，这样可以同时检测到重载的几个方法
                boolean append = name.equals("append") &&
                        owner.equals("java/lang/StringBuilder") &&
                        desc.equals("(Ljava/lang/String;)Ljava/lang/StringBuilder;");
                boolean toString=name.equals("toString") && owner.equals("java/lang/StringBuilder") && desc.equals("()Ljava/lang/String;");
                if (subString){
                    int k=0;
                    Set listAll =new HashSet();
                    for (Type argType : Type.getArgumentTypes(desc)) {
                        int size=argType.getSize();
                        while (size-- > 0){
                            Set taintList=operandStack.get(k);
                            if(taintList.size()>0){
                                listAll.addAll(taintList);
                            }
                            k++;
                        }
                    }
                    listAll.addAll(operandStack.get(k));
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(listAll);
                    return ;
                }

//                //这种情况不需要判断有没有攻击者可控的参数流入，下图告警的情况会在攻击者尝试通过字符串拼接等方式得到一个ProcessBuilder和Runtime才会产生的
                if (classCallMethod){
                    int k=0;
//                    Set listAll =new HashSet();
                    for (Type argType : Type.getArgumentTypes(desc)) {
                        int size=argType.getSize();
                        while (size-- > 0){
                            Set taintList=operandStack.get(k);
                            //因为前面各种方法传递、运算 字符串才会在这里得到完整得结果
                            if(taintList.contains("java.lang.ProcessBuilder")||taintList.contains("java.lang.Runtime")){
                                //这种情况就是企图反射调用java.lang.ProcessBuilder或者java.lang.Runtime。直接调用命令执行方法可能是程序的正常业务功能，但反射调用命令执行方法基本就是攻击者行为。
                                if (!printEvilMessage.contains(1)){
                                    printEvilMessage.add(1);
                                logger.info(Constant.classNameToJspName.get(classFileName)+"------企图调用ProcessBuilder或Runtime，该文件为webshell");
                                Constant.evilClass.add(classFileName);
                                }
                            }
                            k++;
                        }
                    }
                    if(operandStack.get(k).contains("java.lang.ProcessBuilder")||operandStack.get(k).contains("java.lang.Runtime")){
                        if (!printEvilMessage.contains(1)){
                            printEvilMessage.add(1);
                            logger.info(Constant.classNameToJspName.get(classFileName)+"------企图调用ProcessBuilder或Runtime，该文件为webshell");
                        Constant.evilClass.add(classFileName);
                        }
                    }
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    return ;
                }
                if(decodeBuffer){
                    String encodeString="";
                   Set taintList=operandStack.get(0);
                   int taintNum=-1;
                   for(Object taint:taintList){
                       taintNum++;
                       if(taint instanceof String){
                           encodeString=(String)taint;
                           break;                     //todo 新添加的，待测试
                       }else if (taint instanceof Integer){
                           super.visitMethodInsn(opcode, owner, name, desc, itf);
                           operandStack.get(0).addAll(taintList);
                           return;
                       }
                   }
                   if(encodeString.length()>0){
                       String decodeString=new String();
                       try {
                           decodeString=new String(new sun.misc.BASE64Decoder().decodeBuffer(encodeString));
                       } catch (IOException e) {
                           e.printStackTrace();
                       }
                       List   newTaintList= (List) new ArrayList<>(taintList);
                       newTaintList.set(taintNum,decodeString);
                       super.visitMethodInsn(opcode, owner, name, desc, itf);
                       operandStack.get(0).addAll(newTaintList);
                       return;
                   }
                }
                if (exec) {
                    for(Object node:operandStack.get(0)){
                        if( node instanceof Integer){
                            int taintNum= (Integer) node;
                            if(Constant.debug){
                                logger.info("Runtime.exec可被arg"+taintNum+"污染");
                            }
                            if(this.name.equals("_jspService")){
                                if (!printEvilMessage.contains(1)){
                                    printEvilMessage.add(1);
                                logger.info(Constant.classNameToJspName.get(classFileName)+"------Runtime.exec可受request控制，该文件为webshell!!!");
                                Constant.evilClass.add(classFileName);
                                }
                            }
                            //将能够流入到Runtime.exec方法中的入参标记为污染点
                            toEvilTaint.add(taintNum);
                            super.visitMethodInsn(opcode, owner, name, desc, itf);
                            return;
                        }
                    }
                }
                if (append && (operandStack.get(0).size() > 0 || operandStack.get(1).size() > 0)) {
                    Set taintList1=operandStack.get(0);
                    Set taintList2=operandStack.get(1);
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    if (taintList1.size()>0){
                        operandStack.get(0).addAll(taintList1);
                    }
                    if(taintList2.size()>0){
                        operandStack.get(0).addAll(taintList2);
                    }
                    return ;
                }
                if(toString && operandStack.get(0).size()>0){
                    Set taintList=operandStack.get(0);
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(taintList);
                    return ;
                }
            }
            //调用构造方法
            if(opcode==Opcodes.INVOKESPECIAL){
                //除了ProcessBuilder,也都是做污点字符串传递的处理
                boolean processBuilderInit=owner.equals("java/lang/ProcessBuilder")&&name.equals("<init>");
                boolean stringByteInit=owner.equals("java/lang/String")&&name.equals("<init>")&&(desc.equals("([B)V")||desc.equals("([BLjava/lang/String;)V"));
                boolean stringInit=owner.equals("java/lang/String")&&name.equals("<init>");
                boolean stringBuilderInit=owner.equals("java/lang/StringBuilder") && name.equals("<init>") && desc.equals("(Ljava/lang/String;)V");
                if (stringByteInit){
                    Set taintList=operandStack.get(0);
                    for(Object taint:operandStack.get(0)){
                        //获取Opcodes.BIPUSH存放进来的byte数组然后还原原貌，主应对new String(byte[])这种情况，把byte[]还原成String进行污点传递
                        if(taint instanceof ArrayList){
                            int len=((ArrayList)taint).size();
                            byte[] tmp=new byte[len];
                            for(int i=0;i<len;i++){
                                tmp[i]= (byte) (int)(((ArrayList) taint).get(i));
                            }
                            super.visitMethodInsn(opcode, owner, name, desc, itf);
                            operandStack.get(0).add(new String(tmp));
                            return ;
                        }
                        //如果不包含arrayList的byte数组，那么就正常传递污点
                        super.visitMethodInsn(opcode, owner, name, desc, itf);
                        operandStack.get(0).addAll(taintList);
                        return ;
                    }
                }
                if(stringInit){
                    //传递String对象初始化参数中的所有的污点
                    int k=0;
                    Set listAll =new HashSet();
                    for (Type argType : Type.getArgumentTypes(desc)) {
                        int size=argType.getSize();
                        while (size-- > 0){
                            Set taintList=operandStack.get(k);
                            if(taintList.size()>0){
                                listAll.addAll(taintList);
                            }
                            k++;
                        }
                    }
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(listAll);
                    return ;
                }
                if (processBuilderInit){
                    for(Object node:operandStack.get(0)){
                        if( node instanceof Integer){
                            int taintNum= (Integer) node;
                            if(Constant.debug){
                                logger.info("ProcessBuilder可被arg"+taintNum+"污染");
                            }
                            if(this.name.equals("_jspService")){
                                if (!printEvilMessage.contains(1)){
                                    printEvilMessage.add(1);
                                    logger.info(Constant.classNameToJspName.get(classFileName)+"------ProcessBuilder可受request控制，该文件为webshell!!!");
                                Constant.evilClass.add(classFileName);
                                }
                            }
                            toEvilTaint.add(taintNum);
                            super.visitMethodInsn(opcode, owner, name, desc, itf);
                            return;
                        }
                    }
                }

                if(stringBuilderInit && operandStack.get(0).size()>0){
                    Set taintList=operandStack.get(0);
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(taintList);
                    return ;
                }

            }
            if(opcode==Opcodes.INVOKESTATIC){
                boolean isValueOf=name.equals("valueOf") && desc.equals("(Ljava/lang/Object;)Ljava/lang/String;") && owner.equals("java/lang/String");
                if(isValueOf && operandStack.get(0).size()>0){
                    Set taintList=operandStack.get(0);
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(taintList);
                    return ;
                }
            }

            super.visitMethodInsn(opcode, owner, name, desc, itf);
            //把调用其他方法获得的污点进行传递
            if (retSize > 0) {
                operandStack.get(retSize-1).addAll(resultTaint);
            }
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            if(opcode==Opcodes.BIPUSH){
                super.visitIntInsn(opcode, operand);
                operandStack.get(0).add(operand);
                return;
            }
            super.visitIntInsn(opcode, operand);
        }


        @Override
        public void visitInsn(int opcode) {
            if (opcode == Opcodes.AASTORE) {
                Set taintList=operandStack.get(0);
                if(taintList.size()>0){
                    super.visitInsn(opcode);
                    // 这里涉及一个很坑的问题，如果是p[i]="456"+p[i]+"123"这种情况，当执行aastore指令的时候，操作栈中只有三个，super.visitInsn(Opcodes.AASTORE)一调用，栈中空了，再取 operandStack.get(0)会报错
                    if(operandStack.size()>0){
                        operandStack.get(0).addAll(taintList);
                    }
                    return ;
                }
            }
            if (opcode==Opcodes.BASTORE){
                Set taintList=operandStack.get(0);
                super.visitInsn(opcode);
                if(taintList.size()>0){
                    for(Object tmpObj:operandStack.get(0)){
                        if(tmpObj instanceof ArrayList){
                            ((ArrayList) tmpObj).addAll(taintList);
                            return ;
                        }
                    }
                    ArrayList list=new ArrayList<>();
                    list.addAll(taintList);
                    operandStack.set(0,list);
                }
                return ;
            }
            if(opcode==Opcodes.AALOAD){
                //operandStack.get(1)为数组对象
                Set taintList=operandStack.get(1);
                super.visitInsn(opcode);
                if(taintList.size()>0){
                    operandStack.get(0).addAll(taintList);
                }
                return ;
            }
            super.visitInsn(opcode);
        }

        @Override
        public void visitLdcInsn(Object cst) {
            if(cst instanceof String){
                super.visitLdcInsn(cst);
                operandStack.get(0).add(cst);
                return;
            }
            super.visitLdcInsn(cst);
        }
    }

    public static void main(String args[]){
    }
}
