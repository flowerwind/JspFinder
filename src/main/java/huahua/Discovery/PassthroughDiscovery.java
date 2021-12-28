package huahua.Discovery;

import huahua.Constant.Constant;
import huahua.core.CoreMethodAdapter;
import huahua.data.DataFactory;
import huahua.data.DataLoader;
import huahua.data.MethodReference;
import org.apache.log4j.Logger;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.JSRInlinerAdapter;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.*;

public class PassthroughDiscovery {
    private static final Logger logger = Logger.getLogger(PassthroughDiscovery.class);
//    private final List<MethodReference> discoveredMethods = new ArrayList<>();
    private Map<String,Map<MethodReference.Handle, Set<MethodReference.Handle>>> classFileNameToMethodCalls=new HashMap<>();
//    private Map<String,List<MethodReference.Handle>> classFileNameToSortedMethodCalls=new HashMap<>();      //最前面的方法是需要最先观察得方法
    public void discover() throws IOException, ClassNotFoundException {
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
            Constant.classFileNameToSortedMethodCalls.put(classFileName,sortedMethods);
        }
    }

    public static Map<MethodReference.Handle, Set<Integer>> load() throws IOException, ClassNotFoundException {
        Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = new HashMap<>();
        String resource= "/passthrough.dat";
        for (Map.Entry<MethodReference.Handle, Set<Integer>> entry : DataLoader.loadData(resource, new PassThroughFactory())) {
            passthroughDataflow.put(entry.getKey(), entry.getValue());
        }
        return passthroughDataflow;
    }

    public static class PassThroughFactory implements DataFactory<Map.Entry<MethodReference.Handle, Set<Integer>>> {

        @Override
        public Map.Entry<MethodReference.Handle, Set<Integer>> parse(String[] fields) {
            String clazz = fields[0];
            MethodReference.Handle method = new MethodReference.Handle(clazz, fields[1], fields[2]);

            Set<Integer> passthroughArgs = new HashSet<>();
            for (String arg : fields[3].split(",")) {
                if (arg.length() > 0) {
                    passthroughArgs.add(Integer.parseInt(arg));
                }
            }
            return new AbstractMap.SimpleEntry<>(method, passthroughArgs);
        }
        @Override
        public String[] serialize(Map.Entry<MethodReference.Handle, Set<Integer>> entry) {
            if (entry.getValue().size() == 0) {
                return null;
            }

            final String[] fields = new String[4];
            fields[0] = entry.getKey().getOwner();
            fields[1] = entry.getKey().getName();
            fields[2] = entry.getKey().getDesc();

            StringBuilder sb = new StringBuilder();
            for (Integer arg : entry.getValue()) {
                sb.append(Integer.toString(arg));
                sb.append(",");
            }
            fields[3] = sb.toString();

            return fields;
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

    private void calculatePassthroughDataflow() throws IOException, ClassNotFoundException {
        final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;
        if(Constant.passthroughDataflow.size()==0){
            passthroughDataflow = load();
        }else{
            passthroughDataflow=Constant.passthroughDataflow;
        }
        for(String  classFileName:Constant.classFileNameToSortedMethodCalls.keySet()){
            List<MethodReference.Handle> methodCalls=Constant.classFileNameToSortedMethodCalls.get(classFileName);
            for(MethodReference.Handle methodToVisit:methodCalls){
                byte[] classByte=Constant.classNameToByte.get(classFileName);
                ClassReader cr=new ClassReader(classByte);
                PassthroughDataflowClassVisitor passthroughDataflowClassVisitor=new PassthroughDataflowClassVisitor(passthroughDataflow,Opcodes.ASM6,methodToVisit);
                cr.accept(passthroughDataflowClassVisitor,ClassReader.EXPAND_FRAMES);
            }
        }
        Constant.passthroughDataflow=passthroughDataflow;
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
        public void visitInsn(int opcode) {
            switch(opcode) {
                case Opcodes.IRETURN://从当前方法返回int
                case Opcodes.FRETURN://从当前方法返回float
                case Opcodes.ARETURN://从当前方法返回对象引用
                    Set taints=operandStack.get(0);
                    for (Object taint:taints){
                        if(taint instanceof Integer){
                            returnTaint.add((Integer) taint);
                        }
                    }
                    break;
                case Opcodes.LRETURN://从当前方法返回long
                case Opcodes.DRETURN://从当前方法返回double
                    Set taintss=operandStack.get(1);
                    for (Object taint:taintss){
                        if(taint instanceof Integer){
                            returnTaint.add((Integer) taint);
                        }
                    }
                    break;
                case Opcodes.RETURN://从当前方法返回void
                    break;
                default:
                    break;
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
            if(opcode==Opcodes.AASTORE){
                Set taintList=operandStack.get(0);
                super.visitInsn(opcode);
                if(taintList.size()>0){
                    operandStack.get(0).addAll(taintList);
                }
                return ;
            }
            super.visitInsn(opcode);
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String desc) {
            switch (opcode) {
                case Opcodes.GETSTATIC:
                    break;
                case Opcodes.PUTSTATIC:
                    break;
                case Opcodes.GETFIELD:
                    Type type = Type.getType(desc);//获取字段类型
                    if (type.getSize() == 1) {
                        //size=1可能为引用类型
                        Boolean isTransient = null;

                        Set<Integer> taint;
                        taint = operandStack.get(0);
                        super.visitFieldInsn(opcode, owner, name, desc);
                        operandStack.set(0, taint);
                        return;
                    }
                    break;
                case Opcodes.PUTFIELD:
                    break;
                default:
                    throw new IllegalStateException("Unsupported opcode: " + opcode);
            }

            super.visitFieldInsn(opcode, owner, name, desc);
        }


        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            //获取method参数类型
            Type[] argTypes = Type.getArgumentTypes(desc);
            if (opcode != Opcodes.INVOKESTATIC) {
                //如果执行的非静态方法，则把数组第一个元素类型设置为该实例对象的类型，类比局部变量表
                Type[] extendedArgTypes = new Type[argTypes.length+1];
                System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
                extendedArgTypes[0] = Type.getObjectType(owner);
                argTypes = extendedArgTypes;
            }
            //获取返回值类型大小
            int retSize = Type.getReturnType(desc).getSize();

            Set<Integer> resultTaint;
            switch (opcode){
                case Opcodes.INVOKESTATIC:
                case Opcodes.INVOKEINTERFACE:
                case Opcodes.INVOKEVIRTUAL:
                case Opcodes.INVOKESPECIAL:
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

                    //构造方法的调用，意味参数0可以污染返回值
                    if (name.equals("<init>")) {
                        // Pass result taint through to original taint set; the initialized object is directly tainted by
                        // parameters
                        resultTaint = argTaint.get(0);
                    } else {
                        resultTaint = new HashSet<>();
                    }

                    // 前面已做逆拓扑，调用链最末端最先被visit，因此，调用到的方法必然已被visit分析过
                    Set<Integer> passthrough = passthroughDataflow.get(new MethodReference.Handle(owner, name, desc));
                    if (passthrough != null && passthrough.size()>0) {
                        for (Integer passthroughDataflowArg : passthrough) {
                            resultTaint.addAll(argTaint.get(new Integer(passthroughDataflowArg)));
                        }
                    }
                    break;
                default:
                    throw new IllegalStateException("Unexpected value: " + opcode);
            }

            super.visitMethodInsn(opcode, owner, name, desc, itf);
            if (retSize > 0) {
                operandStack.get(retSize-1).addAll(resultTaint);
            }
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
}
