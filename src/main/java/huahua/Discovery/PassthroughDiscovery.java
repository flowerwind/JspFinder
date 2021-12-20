package huahua.Discovery;

import huahua.Constant.Constant;
import huahua.core.CoreMethodAdapter;
import huahua.data.MethodReference;
import huahua.main;
import org.apache.log4j.Logger;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.JSRInlinerAdapter;

import java.io.IOException;
import java.util.*;

public class PassthroughDiscovery {
    private static final Logger logger = Logger.getLogger(PassthroughDiscovery.class);
//    private final List<MethodReference> discoveredMethods = new ArrayList<>();
    private Map<String,Map<MethodReference.Handle, Set<MethodReference.Handle>>> classFileNameToMethodCalls=new HashMap<>();
    private Map<String,List<MethodReference.Handle>> classFileNameToSortedMethodCalls=new HashMap<>();      //最前面的方法是需要最先观察得方法
    public void discover(){
        discoverMethodCalls();
        SortMethodCalls();
        calculatePassthroughDataflow();
    }

    private  void discoverMethodCalls(){
        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodCalls;
        for (String classFileName: Constant.classNameToByte.keySet()){
            byte[] classByte=Constant.classNameToByte.get(classFileName);
            ClassReader cr = new ClassReader(classByte);
            MethodCallDiscoveryClassVisitor methodCallDiscoveryClassVisitor=new MethodCallDiscoveryClassVisitor();
            cr.accept(methodCallDiscoveryClassVisitor,ClassReader.EXPAND_FRAMES);
            methodCalls=methodCallDiscoveryClassVisitor.getMethodCalls();
            classFileNameToMethodCalls.put(classFileName,methodCalls);
//            for (MethodReference.Handle methodClassKey:methodCalls.keySet()){
//                System.out.println("-----------------");
//                if(methodClassKey.getOwner().equals("org/apache/jsp/ProcessBuilder_002dreflect_002dcmd_jsp"))
//                {
//                    System.out.println(methodClassKey.getOwner());
//                    System.out.println(methodClassKey);
//                    System.out.println("-----------------");
//                    System.out.println(methodCalls.get(methodClassKey));
//                    System.out.println("\r\n\r\n");
//                }
//            }
        }
    }

    private void SortMethodCalls(){
        for(String classFileName:classFileNameToMethodCalls.keySet()){
            Map<MethodReference.Handle, Set<MethodReference.Handle>> methodCalls =classFileNameToMethodCalls.get(classFileName);
            Map<MethodReference.Handle, Set<MethodReference.Handle>> outgoingReferences = new HashMap<>();
            for (Map.Entry<MethodReference.Handle, Set<MethodReference.Handle>> entry : methodCalls.entrySet()) {
                MethodReference.Handle method = entry.getKey();
                outgoingReferences.put(method, new HashSet<>(entry.getValue()));
            }

            // Topological sort methods
            logger.debug("Performing topological sort...");
            Set<MethodReference.Handle> dfsStack = new HashSet<>();
            Set<MethodReference.Handle> visitedNodes = new HashSet<>();
            List<MethodReference.Handle> sortedMethods = new ArrayList<>(outgoingReferences.size());
            for (MethodReference.Handle root : outgoingReferences.keySet()) {
                //遍历集合中的起始方法，进行递归搜索DFS，通过逆拓扑排序，调用链的最末端排在最前面，
                // 这样才能实现入参、返回值、函数调用链之间的污点影响
                dfsTsort(outgoingReferences, sortedMethods, visitedNodes, dfsStack, root);
            }
            logger.debug(String.format("Outgoing references %d, sortedMethods %d", outgoingReferences.size(), sortedMethods.size()));
            classFileNameToSortedMethodCalls.put(classFileName,sortedMethods);
        }
    }

    private static void dfsTsort(Map<MethodReference.Handle, Set<MethodReference.Handle>> outgoingReferences,
                                 List<MethodReference.Handle> sortedMethods, Set<MethodReference.Handle> visitedNodes,
                                 Set<MethodReference.Handle> stack, MethodReference.Handle node) {

        if (stack.contains(node)) {
            return;
        }
        if (visitedNodes.contains(node)) {
            return;
        }
        //根据起始方法，取出被调用的方法集
        Set<MethodReference.Handle> outgoingRefs = outgoingReferences.get(node);
        if (outgoingRefs == null) {
            return;
        }

        //入栈，以便于递归不造成类似循环引用的死循环整合
        stack.add(node);
        for (MethodReference.Handle child : outgoingRefs) {
            dfsTsort(outgoingReferences, sortedMethods, visitedNodes, stack, child);
        }
        stack.remove(node);
        visitedNodes.add(node);//记录已被探索过的方法，用于在上层调用遇到重复方法时可以跳过
        sortedMethods.add(node);//递归完成的探索，会添加进来
    }

    private void calculatePassthroughDataflow(){
        final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = new HashMap<>();
        for(String  classFileName:classFileNameToSortedMethodCalls.keySet()){
            List<MethodReference.Handle> methodCalls=classFileNameToSortedMethodCalls.get(classFileName);
            for(MethodReference.Handle methodToVisit:methodCalls){
                byte[] classByte=Constant.classNameToByte.get(classFileName);
                ClassReader cr=new ClassReader(classByte);
                PassthroughDataflowClassVisitor passthroughDataflowClassVisitor=new PassthroughDataflowClassVisitor(passthroughDataflow,Opcodes.ASM6,methodToVisit);
                cr.accept(passthroughDataflowClassVisitor,ClassReader.EXPAND_FRAMES);
            }
        }

    }

    private class PassthroughDataflowClassVisitor extends ClassVisitor{
        private PassthroughDataflowMethodVisitor passthroughDataflowMethodVisitor;
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;
        private final MethodReference.Handle methodToVisit;
        private String name;
        public PassthroughDataflowClassVisitor(Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,int api,MethodReference.Handle methodToVisit){
            super(api);
            this.passthroughDataflow=passthroughDataflow;
            this.methodToVisit=methodToVisit;
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
                logger.info("观察的类为:"+this.name+"     观察的方法为:"+name);
                passthroughDataflowMethodVisitor=new PassthroughDataflowMethodVisitor(passthroughDataflow,Opcodes.ASM6,access,descriptor,mv,this.name,name,signature,exceptions);
                passthroughDataflow.put(new MethodReference.Handle(this.name,name,descriptor),getReturnTaint());
                return new JSRInlinerAdapter(passthroughDataflowMethodVisitor, access, name, descriptor, signature, exceptions);
            }
            return super.visitMethod(access,name,descriptor,signature,exceptions);
        }

        public Set<Integer> getReturnTaint() {
            if (passthroughDataflowMethodVisitor == null) {
                throw new IllegalStateException("Never constructed the passthroughDataflowmethodVisitor!");
            }
            return passthroughDataflowMethodVisitor.returnTaint;
        }
    }

    private class PassthroughDataflowMethodVisitor extends CoreMethodAdapter {
        private final Set<Integer> returnTaint;//被污染的返回数据
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;
        private final int access;
        private final String desc;
        private final String owner;
        private final String name;
        private final boolean isStatic;
        public PassthroughDataflowMethodVisitor(Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,int api,int access,String desc,MethodVisitor mv,String owner,String name,String signature,String[] exceptions){
            super(api,mv,owner,access,name,desc,signature,exceptions);
            this.passthroughDataflow=passthroughDataflow;
            this.returnTaint=new HashSet<>();
            this.access = access;
            this.desc = desc;
            this.owner=owner;
            this.name=name;
            this.isStatic=(access & Opcodes.ACC_STATIC)!=0;
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
            if(opcode==Opcodes.INVOKEINTERFACE){
                boolean isRequestMethod=owner.equals("javax/servlet/http/HttpServletRequest");
                //处理ProcessBuildr马的情况
                boolean arrayListAdd=name.equals("add") && owner.equals("java/util/List");
                if(isRequestMethod && name.substring(0,3).equals("get")){
                    Set taintList=localVariables.get(1);            //单考虑_jspService方法，request对象必然是在本地变量表的1位置的
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(taintList);                   //将request.xxx的返回值设置上request的污点
                    return;
                }
                if (arrayListAdd){
                    int k=0;
                    Set listAll =new HashSet();
                    for (Type argType : Type.getArgumentTypes(desc)) {
                        int size=argType.getSize();
                        while (size-- > 0){
                            Set taintList=operandStack.get(k);
                            listAll.addAll(taintList);
                            k++;
                        }
                    }
                    operandStack.get(k).addAll(listAll);             //所有参数过完之后k就来到了操作数栈中的list对象的位置，如果add方法参数包含可被攻击者控制的值，则list对象添加get-param污点

                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    return ;
                }
            }
            //调用实例方法
            if(opcode==Opcodes.INVOKEVIRTUAL){
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
                    listAll.add(operandStack.get(k));
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(listAll);
                    return ;
                }
                if (classCallMethod){
                    int k=0;
//                    Set listAll =new HashSet();
                    for (Type argType : Type.getArgumentTypes(desc)) {
                        int size=argType.getSize();
                        while (size-- > 0){
                            Set taintList=operandStack.get(k);
                            if(taintList.contains("java.lang.ProcessBuilder")||taintList.contains("java.lang.Runtime")){
                                logger.info("企图调用ProcessBuilder或Runtime，可能为webshell");
                            }
                            k++;
                        }
                    }
                    if(operandStack.get(k).contains("java.lang.ProcessBuilder")||operandStack.get(k).contains("java.lang.Runtime")){
                        logger.info("企图调用ProcessBuilder或Runtime，可能为webshell");
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
                            logger.info("Runtime.exec可被arg"+taintNum+"污染");
                            if(this.name.equals("_jspService")){
                                logger.info(this.owner+"是webshell!!!");
                            }
                            returnTaint.add(taintNum);
                            super.visitMethodInsn(opcode, owner, name, desc, itf);
                            return;
                        }
                    }
                }
                if (append && (operandStack.get(0).size() > 0 || operandStack.get(1).size() > 0)) {
                    Set taintList1=operandStack.get(0);
                    Set taintList2=operandStack.get(1);
                    if(taintList1.size()>0 || taintList2.size()>0){
                        super.visitMethodInsn(opcode, owner, name, desc, itf);
                        operandStack.get(0).addAll(taintList1);
                        operandStack.get(0).addAll(taintList2);
                        return ;
                    }
                }
                if(toString && operandStack.get(0).size()>0){
                    Set taintList=operandStack.get(0);
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(taintList);
                    return ;
                }

                //todo 处理调用恶意类的情况
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

                //todo 前面已做逆拓扑，调用链最末端最先被visit，因此，调用到的方法必然已被visit分析过
                Set<Integer> passthrough = passthroughDataflow.get(new MethodReference.Handle(owner, name, desc));
                if (passthrough != null && passthrough.size()>0) {
                    for (Integer passthroughDataflowArg : passthrough) {
                        returnTaint.addAll(argTaint.get(new Integer(passthroughDataflowArg)));
                    }
                    if(returnTaint.size()>0){
                        //todo 如果调用方法为_jspService，并且污染值在第一位(request参数是_jspService方法第一位，说明恶意类可以被request污染--也就是攻击者可控)
                        if(this.name.equals("_jspService") && returnTaint.contains(1)){
                            logger.info(this.owner+"是webshell!!!");
                        }
                        logger.info("类:"+this.owner+"方法:"+this.name+"调用到被污染方法:"+name);
                        logger.info("污染点为:"+returnTaint);
                    }
                }
            }
            //调用构造方法
            if(opcode==Opcodes.INVOKESPECIAL){
                boolean processBuilderInit=owner.equals("java/lang/ProcessBuilder")&&name.equals("<init>");
                boolean stringByteInit=owner.equals("java/lang/String")&&name.equals("<init>")&&desc.equals("([B)V");
                boolean stringInit=owner.equals("java/lang/String")&&name.equals("<init>");
                boolean stringBuilderInit=owner.equals("java/lang/StringBuilder") && name.equals("<init>") && desc.equals("(Ljava/lang/String;)V");
                if (stringByteInit){
                    Set taintList=operandStack.get(0);
                    for(Object taint:operandStack.get(0)){
                        //获取Opcodes.BIPUSH存放进来的byte数组然后还原原貌
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
                            logger.info("ProcessBuilder可被arg"+taintNum+"污染");
                            if(this.name.equals("_jspService")){
                                logger.info(this.owner+"是webshell!!!");
                            }
                            returnTaint.add(taintNum);
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
                boolean isClassForname=name.equals("forName") && owner.equals("java/lang/Class");
                boolean isValueOf=name.equals("valueOf") && desc.equals("(Ljava/lang/Object;)Ljava/lang/String;") && owner.equals("java/lang/String");
                if(isClassForname){
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
                if(isValueOf && operandStack.get(0).size()>0){
                    Set taintList=operandStack.get(0);            //单考虑_jspService方法，request对象必然是在本地变量表的1位置的
                    super.visitMethodInsn(opcode, owner, name, desc, itf);
                    operandStack.get(0).addAll(taintList);
                    return ;
                }
            }

            super.visitMethodInsn(opcode, owner, name, desc, itf);
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
                    operandStack.get(0).addAll(taintList);
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

    private class MethodCallDiscoveryClassVisitor extends ClassVisitor{
        private String name;
        private Map<MethodReference.Handle, Set<MethodReference.Handle>> methodCalls = new HashMap<>();
        public MethodCallDiscoveryClassVisitor() {
            super(Opcodes.ASM6);
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            if (this.name != null) {
                throw new IllegalStateException("ClassVisitor already visited a class!");
            }
            this.name = name;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            MethodCallDiscoveryMethodVisitor methodCallDiscoveryMethodVisitor = new MethodCallDiscoveryMethodVisitor(
                    api, mv, this.name, name, descriptor,methodCalls);
            return new JSRInlinerAdapter(methodCallDiscoveryMethodVisitor, access, name, descriptor, signature, exceptions);
        }

        public Map<MethodReference.Handle, Set<MethodReference.Handle>> getMethodCalls() {
            return methodCalls;
        }
    }

    private class MethodCallDiscoveryMethodVisitor extends MethodVisitor{
        private Map<MethodReference.Handle, Set<MethodReference.Handle>> methodCalls = new HashMap<>();
        private final Set<MethodReference.Handle> calledMethods;
        private final String name;
        private final String owner;
        private final String desc;
        public MethodCallDiscoveryMethodVisitor(int api, MethodVisitor methodVisitor,final String owner, String name, String desc,Map<MethodReference.Handle, Set<MethodReference.Handle>> methodCalls) {
            super(api, methodVisitor);
            this.name=name;
            this.owner=owner;
            this.desc=desc;
            this.calledMethods = new HashSet<>();
            this.methodCalls=methodCalls;
        }

        @Override
        public void visitCode() {
            methodCalls.put(new MethodReference.Handle(this.owner,this.name,this.desc),this.calledMethods);
            super.visitCode();
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            this.calledMethods.add(new MethodReference.Handle(owner,name,descriptor));
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }

    public static void main(String args[]){
    }
}
